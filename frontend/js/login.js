/* Login page. */
(function () {
  "use strict";

  document.getElementById("login-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var email = document.getElementById("email").value.trim();
    var password = document.getElementById("password").value;
    var btn = document.getElementById("login-btn");
    var err = document.getElementById("login-error");
    btn.disabled = true;
    btn.innerHTML = '<span class="spin"></span> Signing in';
    err.classList.add("hidden");
    API.login(email, password)
      .then(function (res) {
        API.setToken(res.token);
        var role = res.user && res.user.role;
        window.location.href =
          (role === "EMPLOYEE") ? "/app/index.html" : "/app/admin.html";
      })
      .catch(function (ex) {
        err.textContent = ex.message || "Sign-in failed";
        err.classList.remove("hidden");
        btn.textContent = "Sign in";
        btn.disabled = false;
      });
  });
})();