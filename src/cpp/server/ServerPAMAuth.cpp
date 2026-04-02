/*
 * ServerPAMAuth.cpp
 *
 * Copyright (C) 2022 by Posit Software, PBC
 *
 * Unless you have received this program directly from Posit Software pursuant
 * to the terms of a commercial license agreement with Posit Software, then
 * this program is licensed to you under the terms of version 3 of the
 * GNU Affero General Public License. This program is distributed WITHOUT
 * ANY EXPRESS OR IMPLIED WARRANTY, INCLUDING THOSE OF NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Please refer to the
 * AGPL (http://www.gnu.org/licenses/agpl-3.0.txt) for more details.
 *
 */
#include "ServerPAMAuth.hpp"
#include "ServerPAMAuthOverlay.hpp"

#include <core/Thread.hpp>
#include <core/system/Process.hpp>
#include <core/FileSerializer.hpp>
#include <core/system/Crypto.hpp>
#include <core/system/PosixSystem.hpp>
#include <core/system/PosixUser.hpp>
#include <core/system/System.hpp>

#include <core/http/URL.hpp>
#include <core/http/Util.hpp>

#include <shared_core/Error.hpp>
#include <shared_core/json/Json.hpp>
#include <shared_core/SafeConvert.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>
#include <boost/scope_exit.hpp>

#include <server/ServerOptions.hpp>
#include <server/ServerUriHandlers.hpp>

#include <server/auth/ServerAuthHandler.hpp>
#include <server/auth/ServerAuthCommon.hpp>

#include <server/session/ServerSessionProxy.hpp>

#include "ServerLoginPages.hpp"

namespace rstudio {
namespace server {
namespace pam_auth {

using namespace rstudio::core;
using namespace boost::placeholders;

namespace {

void assumeRootPriv()
{
    // RedHat 5 returns PAM_SYSTEM_ERR from pam_authenticate if we're
    // running with geteuid != getuid (as is the case when we temporarily
    // drop privileges). We've also seen kerberos on Ubuntu require
    // priv to work correctly -- so, restore privilliges in the child
    if (core::system::realUserIsRoot())
    {
       Error error = core::system::restorePriv();
       if (error)
       {
          LOG_ERROR(error);
          // intentionally fail forward (see note above)
       }
    }
}

// It's important that URIs be in the root directory, so the cookie
// gets set/unset at the correct scope!
const char * const kDoSignIn = "/auth-do-sign-in";
const char * const kPublicKey = "/auth-public-key";

const char * const kFormAction = "formAction";
const char * const kOtpField = "otp";

bool wantsJsonResponse(const http::Request& request)
{
   return request.headerValue("Accept").find("application/json") != std::string::npos;
}

std::string firstHeaderValue(const std::string& value)
{
   std::vector<std::string> parts;
   boost::algorithm::split(parts, value, boost::is_any_of(","), boost::token_compress_off);
   if (parts.empty())
      return std::string();

   std::string first = parts[0];
   boost::algorithm::trim(first);
   return first;
}

std::string requestRhost(const http::Request& request)
{
   // Prefer RFC7239 Forwarded header (for=), then fall back to X-Forwarded-For.
   std::string forwarded = request.headerValue("Forwarded");
   if (!forwarded.empty())
   {
      boost::smatch matches;
      boost::regex reFor("for=\"?\\[?([^;,\"]+)\\]?\"?",
                         boost::regex_constants::icase);
      if (boost::regex_search(forwarded, matches, reFor) && matches.size() > 1)
         return matches[1];
   }

   std::string xff = firstHeaderValue(request.headerValue("X-Forwarded-For"));
   if (!xff.empty())
      return xff;

   return request.headerValue("X-RStudio-Client-IP");
}

std::string requestFieldValue(const http::Request& request,
                              const http::Fields& parsedFields,
                              bool jsonResponse,
                              const std::string& name)
{
   if (jsonResponse)
      return core::http::util::fieldValue(parsedFields, name);

   return request.formFieldValue(name);
}

void setJsonResponse(const json::Object& payload,
                     http::Response* pResponse)
{
   pResponse->setNoCacheHeaders();
   pResponse->setStatusCode(http::status::Ok);
   pResponse->removeHeader("Location");
   pResponse->setContentType("application/json");
   pResponse->setBody(payload.write());
}

void setJsonErrorResponse(const std::string& error,
                          const std::string& message,
                          http::Response* pResponse)
{
   json::Object payload;
   payload["status"] = "error";
   payload["error"] = error;
   payload["message"] = message;
   setJsonResponse(payload, pResponse);
}

void setJsonOtpRequiredResponse(const std::string& otpSetupMessage,
                                http::Response* pResponse)
{
   json::Object payload;
   payload["status"] = "otp_required";
   payload["otp_setup_message"] = otpSetupMessage;
   setJsonResponse(payload, pResponse);
}

void setJsonSuccessResponse(const std::string& redirect,
                            http::Response* pResponse)
{
   json::Object payload;
   payload["status"] = "ok";
   payload["redirect"] = redirect;
   setJsonResponse(payload, pResponse);
}

std::string getUserIdentifier(const core::http::Request& request)
{
   return auth::common::getUserIdentifier(request);
}

std::string userIdentifierToLocalUsername(const std::string& userIdentifier)
{
   return auth::common::userIdentifierToLocalUsername(userIdentifier);
}

void redirectToLoginPageWithOtp(const http::Request& request,
                                http::Response* pResponse,
                                const std::string& appUri,
                                const std::string& otpSetupMessage,
                                ErrorType error)
{
   core::http::Fields fields;
   fields.push_back(std::make_pair(kAppUri, appUri));
   fields.push_back(std::make_pair(kOtpParam, "1"));
   if (!otpSetupMessage.empty())
      fields.push_back(std::make_pair(kOtpSetupParam, otpSetupMessage));
   if (error != kErrorNone)
      fields.push_back(std::make_pair(kErrorParam, core::safe_convert::numberToString(error)));

   std::string queryString;
   core::http::util::buildQueryString(fields, &queryString);

   std::string signInPath = core::http::URL::uncomplete(request.baseUri(), auth::handler::kSignIn);
   pResponse->setMovedTemporarily(request, signInPath + "?" + queryString);
}

void signIn(const http::Request& request, http::Response* pResponse)
{
   if (server::options().authNone())
   {
      auth::handler::setSignInCookies(request, core::system::username(), false, pResponse);
      pResponse->setMovedTemporarily(request, "./");
      return;
   }

   std::map<std::string,std::string> variables;
   variables["publicKeyUrl"] = http::URL::uncomplete(request.uri(), kPublicKey);
   if (server::options().authEncryptPassword())
      variables[kFormAction] = "action=\"javascript:void\" "
                               "onsubmit=\"submitRealForm();return false\"";
   else
      variables[kFormAction] = "action=\"" + core::http::URL::uncomplete(request.uri(), kDoSignIn) + "\" "
                               "onsubmit=\"return verifyMe()\"";
   const std::string& templatePath = "templates/encrypted-sign-in.htm";
   auth::common::signIn(request, pResponse, templatePath, kDoSignIn, variables);
}

void publicKey(const http::Request&,
               http::Response* pResponse)
{
   std::string exp, mod;
   core::system::crypto::rsaPublicKey(&exp, &mod);
   pResponse->setNoCacheHeaders();
   pResponse->setBody(exp + ":" + mod);
   pResponse->setContentType("text/plain");
}

void doSignIn(const http::Request& request,
              http::Response* pResponse)
{
   bool jsonResponse = wantsJsonResponse(request);
   std::string requestBody = request.body();
   core::http::Fields parsedFields;
   if (jsonResponse)
      core::http::util::parseForm(requestBody, &parsedFields);
   std::string appUri = requestFieldValue(request, parsedFields, jsonResponse, kAppUri);
   std::string encryptedValue = request.formFieldValue("v");
   if (jsonResponse)
      encryptedValue = requestFieldValue(request, parsedFields, jsonResponse, "v");
   std::string otp = requestFieldValue(request, parsedFields, jsonResponse, kOtpField);
   if (!auth::common::validateSignIn(request, pResponse))
   {
      if (jsonResponse)
         setJsonErrorResponse("server", loginErrorMessage(kErrorServer), pResponse);
      else
         redirectToLoginPage(request, pResponse, kAppUri, kErrorServer);
      return;
   }

   bool persist = false;
   std::string username, password;

   if (server::options().authEncryptPassword())
   {
      std::string plainText;
      Error error = core::system::crypto::rsaPrivateDecrypt(encryptedValue,
                                                            &plainText);
      if (error)
      {
         error.addProperty("description", "Failed sign-in - unable to decrypt password - error");
         LOG_ERROR(error);
         if (jsonResponse)
            setJsonErrorResponse("server", loginErrorMessage(kErrorServer), pResponse);
         else
            redirectToLoginPage(request, pResponse, appUri, kErrorServer);
         return;
      }

      std::vector<std::string> parts;
      boost::algorithm::split(parts, plainText, boost::is_any_of("\n"), boost::token_compress_off);
      if (parts.empty())
      {
         LOG_ERROR_MESSAGE("Failed sign-in - missing fields in plaintext");
         if (jsonResponse)
            setJsonErrorResponse("server", loginErrorMessage(kErrorServer), pResponse);
         else
            redirectToLoginPage(request, pResponse, appUri, kErrorServer);
         return;
      }

      persist = requestFieldValue(request, parsedFields, jsonResponse, "persist") == "1";
      username = parts.size() > 0 ? parts[0] : "";
      password = parts.size() > 1 ? parts[1] : "";
      otp = parts.size() > 2 ? parts[2] : "";
   }
   else
   {
      persist = requestFieldValue(request, parsedFields, jsonResponse, "staySignedIn") == "1";
      username = requestFieldValue(request, parsedFields, jsonResponse, "username");
      password = requestFieldValue(request, parsedFields, jsonResponse, "password");
      otp = requestFieldValue(request, parsedFields, jsonResponse, kOtpField);
   }

   // transform to local username
   username = auth::handler::userIdentifierToLocalUsername(username);

   overlay::onUserPasswordUnavailable(username);

   std::string otpSetupMessage;
   PamLoginResult pamResult = pamLogin(username, password, otp, requestRhost(request),
                                       &otpSetupMessage);
   if (pamResult == PamLoginResult::OtpRequired)
   {
      if (jsonResponse)
         setJsonOtpRequiredResponse(otpSetupMessage, pResponse);
      else
         redirectToLoginPageWithOtp(request, pResponse, appUri, otpSetupMessage, kErrorOtpRequired);
      return;
   }

   bool authenticated = pamResult == PamLoginResult::Success;
   if (!auth::common::doSignIn(request, pResponse,
                               username, appUri,
                               persist, authenticated))
   {
     if (jsonResponse)
     {
        if (pamResult == PamLoginResult::Error)
           setJsonErrorResponse("server", loginErrorMessage(kErrorServer), pResponse);
        else
           setJsonErrorResponse("invalid_login", loginErrorMessage(kErrorInvalidLogin), pResponse);
     }
      return;
   }
   overlay::onUserPasswordAvailable(username, password);

   if (jsonResponse)
      setJsonSuccessResponse(pResponse->headerValue("Location"), pResponse);
}

void signOut(const http::Request& request,
             http::Response* pResponse)
{
   std::string username = auth::common::signOut(request, pResponse, getUserIdentifier, auth::handler::kSignIn);
   if (!username.empty())
   {
      overlay::onUserPasswordUnavailable(username, true);
   }
}

} // anonymous namespace


PamLoginResult pamLogin(const std::string& username, const std::string& password,
                        const std::string& otp,
                        const std::string& rhost,
                        std::string* pOtpSetupMessage)
{
   // get path to pam helper
   FilePath pamHelperPath(server::options().authPamHelperPath());
   if (!pamHelperPath.exists())
   {
      LOG_ERROR_MESSAGE("PAM helper binary does not exist at " +
                           pamHelperPath.getAbsolutePath());
      return PamLoginResult::Error;
   }

   // form args
   std::vector<std::string> args;
   args.push_back(username);
   args.push_back("rstudio");
   args.push_back(server::options().authPamRequirePasswordPrompt() ? "1" : "0");
   if (!rhost.empty())
      args.push_back(rhost);

   // don't try to login with an empty password (this hangs PAM as it waits for input)
   if (password.empty())
   {
      LOG_WARNING_MESSAGE("No PAM password provided for user '" + username + "'; refusing login");
      return PamLoginResult::AuthFailed;
   }

   // options (assume priv after fork)
   core::system::ProcessOptions options;
   options.onAfterFork = assumeRootPriv;

   LOG_DEBUG_MESSAGE("PAM login start - running: " + pamHelperPath.getAbsolutePath() + " " + boost::algorithm::join(args, " ") + " <pw>");

   // run pam helper
   core::system::ProcessResult result;
   std::string input = otp.empty() ? password : (password + "\n" + otp);
   Error error = core::system::runProgram(
      pamHelperPath.getAbsolutePath(),
      args,
      input,
      options,
      &result);
   if (error) {
      LOG_ERROR(error);
      return PamLoginResult::Error;
   }

   // check for success
   if (result.exitStatus == 0)
   {
      LOG_DEBUG_MESSAGE("PAM login result: for username: " + username + " returns: authenticated");
      return PamLoginResult::Success;
   }
   else if (result.exitStatus == 2)
   {
      if (pOtpSetupMessage)
         *pOtpSetupMessage = result.stdOut;
      LOG_DEBUG_MESSAGE("PAM login result: for username: " + username + " returns: otp required");
      return PamLoginResult::OtpRequired;
   }
   else
   {
      LOG_DEBUG_MESSAGE("PAM login result: for username: " + username + " returns: auth failed");
      return PamLoginResult::AuthFailed;
   }
}

Error initialize()
{
   // register ourselves as the auth handler
   server::auth::handler::Handler pamHandler;
   auth::common::prepareHandler(pamHandler,
                                signIn,
                                "", // defined below
                                userIdentifierToLocalUsername,
                                getUserIdentifier);
   pamHandler.signOut = signOut;
   if (overlay::canSetSignInCookies())
      pamHandler.setSignInCookies = boost::bind(auth::common::setSignInCookies, _1, _2, _3, boost::none, _4);
   auth::handler::registerHandler(pamHandler);

   // add pam-specific auth handlers
   uri_handlers::addBlocking(kDoSignIn, doSignIn);
   uri_handlers::addBlocking(kPublicKey, publicKey);

   // initialize overlay
   Error error = overlay::initialize();
   if (error)
      return error;

   // initialize crypto
   return core::system::crypto::rsaInit();
}

} // namespace pam_auth
} // namespace server
} // namespace rstudio
