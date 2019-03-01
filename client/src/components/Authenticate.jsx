import React, { Component } from 'react';
import PropTypes from 'prop-types';

class Authenticate extends Component
{
    static propTypes = {
        member: PropTypes.object,
    }

    constructor()
    {
        const { member: { methods } } = this.props;
        this.setActiveMethod.bind(this);
        this.setActiveMethod(methods[0]);
    }

    /**
     * Set the current method the user will use to complete authentication
     * @param {Object} method
     */
    setActiveMethod(method) {
        const { member: { methods } } = this.props;
        this.setState({
            activeMethod: method.component, // inject me?
            otherMethods: methods.filter(
                (otherMethod) => otherMethod.name !== method.name // or other suitably unique identifier
            ),
        });
    }

    /**
     * If the half-logged in member has more than one authentication method set up, show a list of
     * others they have enabled that could also be used to complete authentication and log in.
     */
    renderOtherMethods()
    {
        const { otherMethods } = this.state;

        if (!otherMethods) {
            return null;
        }

        return (
            <div>
                <h2>Or choose another method</h2>
                <ul>
                    {otherMethods.map((method) => (
                        <li><a onclick={() => this.setActiveMethod(method)}>{method.name}</a></li>
                    ))}
                </ul>
            </div>
        );
    }

    render()
    {
        const { activeMethod } = this.state;
        return (
            <div>
                <h1>Authenticate</h1>
                <activeMethod member={member} />
                {this.renderOtherMethods()}
            </div>
        );
    }
}

export default Authenticate;
