function loginSuccess(result) {
    accessToken = result.access_token;
    userId = result.id;
    localStorage.setItem("token", accessToken);
    localStorage.setItem("userId", userId);

    successNotify("You have successfully logged in!");

    setTimeout(() => window.location = "/dashboard", 2000);
}

function registerSuccess(result) {
    successNotify(result);
    window.location = "/#login";
}

$("input#submit-login").on("click", () => {
    email = $("input#login-email").val();
    password = $("input#login-password").val();

    $.ajax({
        url: "/api/auth/login",
        type: "POST",
        data: JSON.stringify({email: email, password: password}),
        dataType: "json",
        contentType: "application/json",
        success: (data) => handleResponse(data, loginSuccess),
        error: errorCallback
    });
});

$("input#submit-register").on("click", () => {
    username = $("input#register-username").val();
    email = $("input#register-email").val();
    password = $("input#register-password").val();

    $.ajax({
        url: "/api/auth/register",
        type: "POST",
        data: JSON.stringify({
            username: username, email: email, password: password
        }),
        dataType: "json",
        contentType: "application/json",
        success: (data) => handleResponse(data, registerSuccess),
        error: errorCallback
    });
});