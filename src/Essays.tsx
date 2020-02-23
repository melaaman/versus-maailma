import React from 'react';
import { OnFiction } from "./essays/OnFiction";
import { Link } from "react-router-dom";
import { Lectio } from "./essays/Lectio";

export const collection1 = [
    OnFiction,
    Lectio
];


export const Essays: React.FunctionComponent<{}> = () => {

    return (
        <div style={{ textAlign: "justify" }}>
            {collection1.map(essay => {
                return (
                    <Link key={essay.url} to={"/esseita/" + essay.url}>
                        <div style={{ letterSpacing: "0", color: "black", marginBottom: "20px" }} >
                            <i style={{ marginRight: "20px" }} className="align left icon" />
                            {essay.title.toUpperCase()}
                        </div>
                    </Link>
                );
            })}
        </div>
    )
}