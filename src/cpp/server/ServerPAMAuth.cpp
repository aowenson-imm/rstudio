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
#include <shared_core/SafeConvert.hpp>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/lock_guard.hpp>
#include <boost/thread/mutex.hpp>

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
const int kOtpNonceTtlSeconds = 120;
const char * const kOtpField = "otp";
const char * const kOtpNonceField = "otpNonce";

struct OtpNonceEntry
{
   std::string username;
   std::string password;
   std::string userAgent;
   boost::posix_time::ptime expiresAt;
};

boost::posix_time::ptime nowUtc()
{
   return boost::posix_time::microsec_clock::universal_time();
}

void secureClear(std::string* value)
{
   if (!value)
      return;
   std::fill(value->begin(), value->end(), '\0');
   value->clear();
}

bool isExpired(const OtpNonceEntry& entry)
{
   return entry.expiresAt <= nowUtc();
}

// Store cached OTP state so secrets can be wiped before entries are erased.
class OtpNonceCache : boost::noncopyable
{
public:
   std::string store(const OtpNonceEntry& entry)
   {
      boost::lock_guard<boost::mutex> lock(mutex_);

      std::string nonce = core::system::generateUuid();
      entries_[nonce] = entry;
      return nonce;
   }

   bool lookup(const std::string& nonce,
               const std::string& userAgent,
               OtpNonceEntry* pEntry)
   {
      boost::lock_guard<boost::mutex> lock(mutex_);
      // lookup
      std::map<std::string, OtpNonceEntry>::iterator it;
      if (!_lookup(nonce, userAgent, &it)) return false;
      if (pEntry) *pEntry = it->second;
      return true;
   }

   bool consume(const std::string& nonce,
                const std::string& userAgent,
                OtpNonceEntry* pEntry)
   {
      boost::lock_guard<boost::mutex> lock(mutex_);
      // lookup
      std::map<std::string, OtpNonceEntry>::iterator it;
      if (!_lookup(nonce, userAgent, &it)) return false;
      if (pEntry) *pEntry = it->second;
      // consume
      secureClear(&it->second.password);
      entries_.erase(it);
      return true;
   }

private:
   bool _lookup(const std::string& nonce,
                const std::string& userAgent,
                std::map<std::string, OtpNonceEntry>::iterator* pIt)
    {
      std::map<std::string, OtpNonceEntry>::iterator it = entries_.find(nonce);
      if (it == entries_.end())
         return false;

      if (isExpired(it->second) ||
          (!it->second.userAgent.empty() && it->second.userAgent != userAgent))
      {
         secureClear(&it->second.password);
         entries_.erase(it);
         return false;
      }

      *pIt = it;
      return true;
   }

   boost::mutex mutex_;
   std::map<std::string, OtpNonceEntry> entries_;
};

OtpNonceCache s_otpNonceCache;

std::string createOtpNonce(const std::string& username,
                           const std::string& password,
                           const std::string& userAgent)
{
   OtpNonceEntry entry;
   entry.username = username;
   entry.password = password;
   entry.userAgent = userAgent;
   entry.expiresAt = nowUtc() + boost::posix_time::seconds(kOtpNonceTtlSeconds);

   return s_otpNonceCache.store(entry);
}

bool lookupOtpNonce(const std::string& nonce,
                    const std::string& userAgent,
                    OtpNonceEntry* pEntry)
{
   if (nonce.empty()) return false;

   return s_otpNonceCache.lookup(nonce, userAgent, pEntry);
}

bool consumeOtpNonce(const std::string& nonce,
                     const std::string& userAgent,
                     OtpNonceEntry* pEntry)
{
   if (nonce.empty()) return false;

   return s_otpNonceCache.consume(nonce, userAgent, pEntry);
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
                                const std::string& otpNonce,
                                ErrorType error)
{
   core::http::Fields fields;
   fields.push_back(std::make_pair(kAppUri, appUri));
   fields.push_back(std::make_pair(kOtpParam, "1"));
   fields.push_back(std::make_pair(kOtpNonceParam, otpNonce));
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
   std::string appUri = request.formFieldValue(kAppUri);
   if (!auth::common::validateSignIn(request, pResponse))
   {
      redirectToLoginPage(request, pResponse, kAppUri, kErrorServer);
      return;
   }

   bool persist = false;
   std::string username, password, otp;
   std::string otpNonce = request.formFieldValue(kOtpNonceField);

   if (server::options().authEncryptPassword()) {
      std::string encryptedValue = request.formFieldValue("v");
      std::string plainText;
      Error error = core::system::crypto::rsaPrivateDecrypt(encryptedValue, &plainText);
      if (error) {
         error.addProperty("description", "Failed sign-in - unable to decrypt password - error");
         LOG_ERROR(error);
         redirectToLoginPage(request, pResponse, appUri, kErrorServer);
         return;
      }

      std::vector<std::string> parts;
      boost::algorithm::split(parts, plainText, boost::is_any_of("\n"), boost::token_compress_off);
      if (parts.empty()) {
         LOG_ERROR_MESSAGE("Failed sign-in - missing fields in plaintext");
         redirectToLoginPage(request, pResponse, appUri, kErrorServer);
         return;
      }

      persist = request.formFieldValue("persist") == "1";
      username = parts.size() > 0 ? parts[0] : "";
      password = parts.size() > 1 ? parts[1] : "";
      otp = parts.size() > 2 ? parts[2] : "";
   } else {
      persist = request.formFieldValue("staySignedIn") == "1";
      username = request.formFieldValue("username");
      password = request.formFieldValue("password");
      otp = request.formFieldValue(kOtpField);
   }

   if (!otpNonce.empty()) {
      OtpNonceEntry entry;
      if (!lookupOtpNonce(otpNonce, request.userAgent(), &entry)) {
         redirectToLoginPage(request, pResponse, appUri, kErrorOtpExpired);
         return;
      }

      if (otp.empty()) {
         redirectToLoginPageWithOtp(request, pResponse, appUri, otpNonce, kErrorOtpRequired);
         return;
      }

      if (!consumeOtpNonce(otpNonce, request.userAgent(), &entry)) {
         redirectToLoginPage(request, pResponse, appUri, kErrorOtpExpired);
         return;
      }

      username = entry.username;
      password = entry.password;
   }

   // transform to local username
   username = auth::handler::userIdentifierToLocalUsername(username);

   overlay::onUserPasswordUnavailable(username);

   PamLoginResult pamResult = pamLogin(username, password, otp);
   if (pamResult == PamLoginResult::OtpRequired) {
      std::string nonce = createOtpNonce(username, password, request.userAgent());
      redirectToLoginPageWithOtp(request, pResponse, appUri, nonce, kErrorOtpRequired);
      return;
   }

   bool authenticated = pamResult == PamLoginResult::Success;
   if (!auth::common::doSignIn(request, pResponse,
                               username, appUri,
                               persist, authenticated))
   { return; }
   overlay::onUserPasswordAvailable(username, password);
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


PamLoginResult pamLogin(const std::string& username,
                        const std::string& password,
                        const std::string& otp)
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

   // don't try to login with an empty password (this hangs PAM as it waits for input)
   if (password.empty()) {
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
   if (result.exitStatus == 0) {
      LOG_DEBUG_MESSAGE("PAM login result: for username: " + username + " returns: authenticated");
      return PamLoginResult::Success;
   } else if (result.exitStatus == 2) {
      LOG_DEBUG_MESSAGE("PAM login result: for username: " + username + " returns: otp required");
      return PamLoginResult::OtpRequired;
   } else {
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
