import React, { Component } from 'react';
import PropTypes from 'prop-types';
import Authenticate from './Authenticate';
import Register from './Register';
import fetch from 'isomorphic-fetch';
import Login from './Login';

class MultiFactorApp extends Component
{
    static propTypes = {
        id: PropTypes.string,
        schemaURL: PropTypes.string,
    }

    constructor()
    {
        this.state = {
            schema: null,
        }
    }

    componentDidMount()
    {
        const thisComponent = this;
        const { schemaURL } = this.props;
        return fetch(schemaURL)
            .then((response) => response.json())
            .then((schemaData) => thisComponent.setState({
                schema: schemaData,
            }));
    }

    /**
     * Directs the flow of the log in process. Three factors play into this:
     * - Schema: all information comes from a JSON schema fetched on mount {@see componentDidMount}
     * - Member: object - the logged in member, null if no one is (partially) logged in yet
     * - Login: boolean - true if member is logging in (show other factors)
     *
     * If Login is false, this indicates that a member is fully authenticated. We can show the log
     * out button, and/or the ability to register for other authentication factor methods.
     *
     * flow proceeds as follows:
     * 1. no schema: error.
     * 2. schema, no member: login
     * 3. schema, member, not login: register for a MFA method
     * 4. schema, member, login: show more authentication factors
     */
    render()
    {
        const { id } = this.props;
        const { schema } = this.state;

        if (!schema) {
            throw Exception('uh oh.')
        }

        const { member, login } = schema;

        if (!member) {
            return <Login />
        }

        if (!login) {
            return <Register {...schema} />;
        }

        return <div id={id}>
            <Authenticate {...schema} />
        </div>;
    }
}

export default MultiFactorApp;
