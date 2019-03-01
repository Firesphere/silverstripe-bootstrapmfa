import React from 'react';

/**
 * Show the start of the log in flow - the log in form.
 */
export default (loginURl, ...props) => (
    <form action={loginURL} method="POST" class="mfa__login-form">
        <input name="username" type="text" />
        <input name="password" type="password" />
        <input name="login" type="submit" />
    </form>
);
