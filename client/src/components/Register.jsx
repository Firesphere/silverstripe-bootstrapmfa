import React, { Component } from 'react';
import PropTypes from 'prop-types';

class Register extends Component
{
    static propTypes = {
        member: PropTypes.object,
        availableMethods: PropTypes.arrayOf(PropTypes.object)
    }

    constructor()
    {
        this.state = {
            registrationComponent: null,
        };
    }

    /**
     * Set the MFA method the user is registering for
     * @param {Object} method
     */
    getMethodRegistrationHandler(method)
    {
        return () => this.setState({
            registrationComponent: method.component, //resolve with injector here?
        })
    }

    /**
     * If the site has more than one multi factor method enabled, show others a user can register
     * @param {Array} registerableMethods Available methods the user has not already set up
     */
    renderMethods(registerableMethods)
    {
        if (!registerableMethods) {
            return null;
        }

        return (
            <div>
                <h1>Register an authentication method</h1>
                <ul>
                    {registerableMethods.map((method) => (
                        <li>
                            <a onclick={this.getMethodRegistrationHandler(method)}>
                                {method.name}
                            </a>
                        </li>
                    ))}
                </ul>
            </div>
        );
    }

    render()
    {
        const { availableMethods, methods: { member } } = this.props;
        const registerableMethods = availableMethods.filter(
            (method) => method.name !== methods[method].name // 'unique' identifier could be better
        );
        return (
            <div>
                <div class="mfa__log-out">
                    <a href="Security/logout">Log out</a>
                </div>
                { registrationComponent || this.renderMethods(registerableMethods) }
            </div>
        );
    }
}

export default Register;
