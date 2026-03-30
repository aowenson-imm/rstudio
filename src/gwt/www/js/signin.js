/*
 * signin.js
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

// Global variable; tracks URL for sign-in response
var responseURL = "";

// Global variable; tracks whether an active sign-in is in progress
var activeSignIn = false;

function setSigningInState(signingIn) {
   var staySignedInEle = document.getElementById('staySignedIn');
   var signinButton = document.getElementById('signinbutton');
   var spinner = document.getElementById('spinner');
   var progress = document.getElementById('progress-message');
   var userEle = document.getElementById('username');
   var passwordEle = document.getElementById('password');
   var otpEle = document.getElementById('otp');

   activeSignIn = signingIn;

   if (staySignedInEle !== null)
      staySignedInEle.readOnly = signingIn;

   if (signinButton !== null) {
      signinButton.disabled = signingIn;
      signinButton.classList.toggle('disabled', signingIn);
   }

   if (spinner !== null)
      spinner.classList.toggle('signin-hidden', !signingIn);

   if (progress !== null)
      progress.innerText = signingIn ? "Signing in" : "";

   if (userEle !== null)
      userEle.disabled = signingIn;
   if (passwordEle !== null)
      passwordEle.disabled = signingIn;
   if (otpEle !== null)
      otpEle.disabled = signingIn;
}

function clearError() {
   var errorDiv = document.getElementById('errorpanel');
   if (errorDiv !== null)
      errorDiv.style.display = 'none';

   var liveError = document.getElementById('live-error');
   if (liveError !== null)
      liveError.innerText = '';
}

function showOtpChallenge() {
   var credentialGroup = document.getElementById('credentialgroup');
   var otpGroup = document.getElementById('otpgroup');
   var otpRequiredEle = document.getElementById('otpRequired');
   var otpRequiredRealEle = document.getElementById('otpRequiredReal');
   var userEle = document.getElementById('username');
   var passwordEle = document.getElementById('password');
   var otpEle = document.getElementById('otp');

   setSigningInState(false);

   if (credentialGroup !== null)
      credentialGroup.style.display = 'none';
   if (otpGroup !== null)
      otpGroup.style.display = 'block';
   if (otpRequiredEle !== null)
      otpRequiredEle.value = '1';
   if (otpRequiredRealEle !== null)
      otpRequiredRealEle.value = '1';
   if (userEle !== null)
      userEle.disabled = true;
   if (passwordEle !== null)
      passwordEle.disabled = true;
   if (otpEle !== null) {
      otpEle.disabled = false;
      otpEle.focus();
   }

   clearError();
}

/**
 * Ensure error region is spoken by a screen reader.
 */
function speakError() {
   document.getElementById("live-error").innerText = document.getElementById("errortext").innerText;
}

/**
 * Verifies the sign-in form, returning true if sign in should proceed and false
 * if there's a problem.
 */
function verifyMe() {
   // Don't allow submitting the form if disabled
   if (document.getElementById('signinbutton').disabled) {
      return false;
   }

   var otpRequiredEle = document.getElementById('otpRequired');
   var otpEle = document.getElementById('otp');
   var otpRequired = otpRequiredEle !== null && otpRequiredEle.value === '1';

   // If a username is present, ensure it has a value unless we're in OTP-only flow
   var userEle = document.getElementById('username');
   if (userEle !== null && !otpRequired) {
     if (userEle.value === '') {
        userEle.focus();
        showError('You must enter a username');
        return false;
     }
   }

   // If a password element is present, ensure it has a value unless we're in OTP-only flow
   var passwordEle = document.getElementById('password');
   if (passwordEle !== null && !otpRequired) {
     if (passwordEle.value === '') {
        passwordEle.focus();
        showError('You must enter a password');
        return false;
     }
   }

   if (otpRequiredEle !== null && otpEle !== null) {
     if (otpRequiredEle.value === '1' && otpEle.value === '') {
        otpEle.focus();
        showError('You must enter a 2FA code');
        return false;
     }
   }

   setSigningInState(true);

   // Form is valid
   return true;
}

/**
 * Displays an error in the designated error panel.
 */
function showError(errorMessage) {
   var errorDiv = document.getElementById('errorpanel');
   errorDiv.innerHTML = '';
   var errorp = document.createElement('p');
   errorp.id = "errortext";
   errorDiv.appendChild(errorp);
   if (typeof(errorp.innerText) === 'undefined')
      errorp.textContent = errorMessage;
   else
      errorp.innerText = errorMessage;
   errorDiv.style.display = 'block';
   speakError();
}

/**
 * Prepares the form to be submitted by encrypting the username and password.
 */
function prepare() {
   // Ensure the form is valid before proceeding
   if (!verifyMe())
      return false;

   try {
      var usernameEle = document.getElementById('username');
      var passwordEle = document.getElementById('password');
      var otpEle = document.getElementById('otp');
      var payload = (usernameEle ? usernameEle.value : "") + "\n" +
                    (passwordEle ? passwordEle.value : "") + "\n" +
                    (otpEle ? otpEle.value : "");
      var xhr = new XMLHttpRequest();
      var metas = document.getElementsByTagName("meta");
      var url = "";
      for (var i = 0; i < metas.length; i++) {
         if (metas[i].getAttribute("name") === "public-key-url") {
            url = metas[i].getAttribute("content");
            break;
         }
      }
      if (url === "") {
         setSigningInState(false);
         showError("Cannot determine server's public key for password encryption;" +
                   "missing <meta> tag.");
         return;
      }

      xhr.open("GET", url, true);
      xhr.onreadystatechange = function() {
         try {
            if (xhr.readyState == 4) {
               if (xhr.status != 200) {
                  var errorMessage;
                  if (xhr.status == 0)
                     errorMessage = "Error: Could not reach server--check your internet connection";
                  else
                     errorMessage = "Error: " + xhr.statusText;
                  setSigningInState(false);
                  showError(errorMessage);
               }
               else {
                  var response = xhr.responseText;
                  var chunks = response.split(':', 2);
                  var exp = chunks[0];
                  var mod = chunks[1];
                  encrypt(payload, exp, mod).then(function (result) {
                     document.getElementById('persist').value = document.getElementById('staySignedIn').checked ? "1" : "0";
                     if (result.alg) {
                        document.getElementById('package').value = '$' + result.alg + '$' + result.ct;
                     } else {
                        document.getElementById('package').value = result.ct;
                     }
                     document.getElementById('clientPath').value = window.location.pathname;
                     console.log("signin prepare", {
                        otpRequired: document.getElementById('otpRequiredReal').value,
                        packageLength: document.getElementById('package').value.length
                     });
                     submitPreparedForm();
                  }).catch(function (exception) {
                     setSigningInState(false);
                     showError("Error: " + exception);
                  });
               }
            }
         } catch (exception) {
            setSigningInState(false);
            showError("Error: " + exception);
         }
      };
      xhr.send(null);
   } catch (exception) {
      setSigningInState(false);
      showError("Error: " + exception);
   }
}

/**
 * Submits the encrypted credentials and interprets the auth response.
 */
function submitPreparedForm() {
   var form = document.realform;
   var xhr = new XMLHttpRequest();
   var formData = new URLSearchParams(new FormData(form));
   console.log("signin submit", {
      action: form.action,
      payloadLength: formData.toString().length,
      packageLength: document.getElementById('package').value.length
   });

   xhr.open(form.method || "POST", form.action, true);
   xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
   xhr.setRequestHeader("Accept", "application/json");
   xhr.onreadystatechange = function() {
      if (xhr.readyState !== 4)
         return;

      try {
         if (xhr.status !== 200) {
            setSigningInState(false);
            showError(xhr.status === 0 ?
               "Error: Could not reach server--check your internet connection" :
               "Error: " + xhr.statusText);
            return;
         }

         var response = JSON.parse(xhr.responseText);
         if (response.status === "ok") {
            window.location = response.redirect || "./";
         } else if (response.status === "otp_required") {
            showOtpChallenge();
         } else {
            setSigningInState(false);
            showError(response.message || "Temporary server error, please try again");
         }
      } catch (exception) {
         setSigningInState(false);
         showError("Error: " + exception);
      }
   };
   xhr.send(formData.toString());
}

/**
 * Submits the sign-in form after preparing by encrypting secrets.
 */
function submitRealForm() {
  if (prepare()) {
    return false;
  }
  return false;
}

/**
 * Checks to see if the user has already signed in via another tab.
 */
function pollForSignin() {
  if (activeSignIn)
     return;

  var xhr = new XMLHttpRequest();
  xhr.open("GET", "./", true);
  xhr.onreadystatechange = function() {
     if (activeSignIn)
       return;
     try {
        if (xhr.readyState === 4) {
           setTimeout(pollForSignin, 3000);
           if (xhr.status === 200) {
              var isSignIn = false;
              var url = xhr.responseURL.split('?')[0];
              var href = location.href.split('?')[0];
              var isSignIn = url === href;
              var controls = document.getElementById("controls");
              var goback = document.getElementById("goback");
              if (isSignIn) {
                 // This is the sign-in page; no external sign-in has occurred
                 controls.classList.remove('signinhidden');
                 goback.classList.add('signinhidden');
              } else {
                 // This is a different page; the user has signed in via another tab.
                 responseURL = url;
                 controls.classList.add('signinhidden');
                 goback.classList.remove('signinhidden');
              }
           }
        }
     } catch (exception) {
       showError("Error: " + exception);
     }
   };
   xhr.send(null);
}

window.addEventListener("load", function() {
   // Is this sign-in form interactive? (i.e., must you enter a username?)
   var userEle = document.getElementById('username');

   if (userEle === null) {
      // No username element; place focus on the sign in button if we have one
      var buttonEle = document.getElementById('signinbutton');
      if (buttonEle !== null) {
         buttonEle.focus();
      }
   } else {
      // Place focus on the username element if it exists
      userEle.focus();

      // Begin polling for sign-ins from other tabs (we only do this for interactive forms)
      setTimeout(pollForSignin, 3000);
   }


   // If we have an error panel, ensure it is announced to screen readers
   var errorPanel = document.getElementById('errorpanel');

   if (errorPanel !== null) {
     var displayProp = window.getComputedStyle(errorPanel, null).getPropertyValue("display");
     if (displayProp !== "none") {
        document.title = "Error: RStudio Sign In Failed";
        // If error message displayed, give time for screen reader to catch up then
        // copy error message to aria-live region to trigger announcement
        setTimeout(function () {
           speakError();
        }, 2000);
     }
   }
});
