function setupJsForm() {
    var errorParagraphs = {
        "credentials": document.getElementById("credentials-error"),
        "csrf": document.getElementById("csrf-error"),
        "request": document.getElementById("request-error"),
    }
    function setFormError(error) {
        for (var otherError in errorParagraphs) {
            if (otherError === error) {
                errorParagraphs[otherError].classList.remove("hidden");
            } else {
                errorParagraphs[otherError].classList.add("hidden");
            }
        }
    }

    var submitButtonNormal = document.getElementById("submit-button--normal");
    var submitButtonLoading = document.getElementById("submit-button--loading");
    var lastLoading = false;
    function setIsLoading(loading) {
        if (loading === lastLoading)
            return;
        if (loading) {
            submitButtonNormal.classList.add("hidden");
            submitButtonLoading.classList.remove("hidden");
        } else {
            submitButtonNormal.classList.remove("hidden");
            submitButtonLoading.classList.add("hidden");
        }
        lastLoading = loading;
    }

    var passwordField = document.getElementById("password-field");
    var totpField = document.getElementById("totp-field");
    function onSubmit(e) {
        // Don't continue if there is anything invalid
        if (!e.target.checkValidity())
            return;

        fetch(window.location.href, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/x-log-in-response",
                "Custom-Header-For-CSRF-Prevention": "1",
            },
            body: new URLSearchParams(new FormData(e.target)).toString(),
            credentials: "same-origin",
            mode: "same-origin",
            referrerPolicy: "no-referrer",
        }).then(function(response) {
            if (!response.ok)
                throw new Error("non OK server response");
            return response.json();
        }).then(function(errorType) {
            if (errorType === null) {
                // Successfully logged in, so we can reload the page
                window.location.reload();
            } else {
                setIsLoading(false);
                setFormError(errorType in errorParagraphs ? errorType : "request");
            }
        }).catch(function(err) {
            console.error("log in request failed", err);
            
            setIsLoading(false);
            setFormError("request");
        });

        setIsLoading(true);

        // Reset fields
        passwordField.value = "";
        totpField.value = "";
    }

    var form = document.getElementById("log-in-form");
    form.addEventListener("submit", function(e) {
        try {
            if (!lastLoading)
                onSubmit(e);

            // Only prevent form submission at the end, if there was no error, so that
            // older browser that don't support fetch will fallback to normal form
            // submission without JS.
            e.preventDefault();
        } catch (err) {
            console.warn("failed to send XHR request, falling back to standard form", err);
        }
    });
    // Remove the ugly native validation bubbles
    form.setAttribute("novalidate", true);
}

var browserSupported = HTMLFormElement.prototype.checkValidity !== undefined && Array.prototype.forEach !== undefined && typeof URLSearchParams === "function" && typeof FormData === "function" && typeof fetch === "function";
if (browserSupported) {
    try {
        setupJsForm();
    } catch (err) {
        console.warn("failed to setup JS form, falling back to standard form", err);
    }
}
