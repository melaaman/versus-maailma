import React from 'react';
import {
    Switch,
    Route,
    useLocation
} from "react-router-dom";
import { Home } from "./Home";
import { Essays } from "./Essays";
import { ShortTexts } from "./ShortTexts";
import { Essay } from "./Essay";
import { collection1 } from "./entities";
import './AppContainer.scss';

export const AppContainer = () => {
    const location = useLocation();

    let essayIndex = -1;

    const lastBackslashIndex = location.pathname.lastIndexOf("/");
    collection1.forEach((essay, index) => {
        const lastPathItem = location.pathname.slice(lastBackslashIndex + 1);
        if (lastPathItem === essay.url) {
            essayIndex = index;
        }
    });

    return (
        <div className="ui main text container">
            <Switch>
                <Route exact path="/esseita" component={Essays}>
                </Route>
                <Route exaxt path={"/esseita/:essee"}>
                    <Essay essay={collection1[essayIndex]} />
                </Route>
                <Route exact path="/lyhyesti" component={ShortTexts} />
                <Route exact path="/" component={Home} />
            </Switch>
        </div>
    )
}