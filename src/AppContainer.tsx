import React from 'react';
import {
    Switch,
    Route
} from "react-router-dom";
import { Home } from "./Home";
import { Essays } from "./Essays";
import { ShortTexts } from "./ShortTexts";
import './AppContainer.scss';

export const AppContainer = () => {
    return (
        <div className="ui main text container">
            <Switch>
                <Route path="/essays">
                    <Essays />
                </Route>
                <Route path="/shortly">
                    <ShortTexts />
                </Route>
                <Route path="/">
                    <Home />
                </Route>
            </Switch>
        </div>
    )
}