function checkUserToken(token) {
    return $.ajax({
        type: 'GET',
        url: "http://ysjcs.net:5004/check_user_token?token=" + token,
        async: true,
        error: function() {
            alert("Session Expired, Please login again.");
            localStorage.clear();
            window.location.href = 'index.html';
        }
    });
}

function checkAdminToken(token) {
    return $.ajax({
        type: 'GET',
        url: "http://ysjcs.net:5004/check_admin_token?token=" + token,
        async: true,
        success: function() {
            $('#navigation').append("<li><a id='admin_btn'>Admin stuff</a></li>");
            $('#admin_btn').on('click', function() {
                onAdminNavClick();
            });
        }
    });
}

function onAdminNavClick() {
    window.location.href = 'admin_control.html';
}

function isEmpty(text) {
    return text === "";
}

function isUndefined(item) {
    return item === undefined;
}


$(document).ready(function() {
    // Enable Logout button
    $('#logoutButton').on('click', function() {
        localStorage.clear()
        window.location.href = 'index.html'
    });
}); 
