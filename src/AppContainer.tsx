import React from 'react';
import {
    Switch,
    Route,
    useLocation
} from "react-router-dom";
import { Home } from "./Home";
import { Essays, collection1 } from "./Essays";
import { ShortTexts } from "./ShortTexts";
import './AppContainer.scss';
import { Essay } from "./Essay";

export const AppContainer = () => {
    const location = useLocation();

    const pathIndex = location.pathname.lastIndexOf("/");
    let essayIndex = -1;
    collection1.forEach((essay, index) => {
        const lastItem = location.pathname.slice(pathIndex + 1);
        if (lastItem === essay.url) {
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