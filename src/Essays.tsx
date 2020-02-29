import React from 'react';
import { OnFiction } from "./essays/OnFiction";
import { Link } from "react-router-dom";
import { Lectio } from "./essays/Lectio";
import { List } from "semantic-ui-react";

export const collection1 = [
    OnFiction,
    Lectio
];


export const Essays: React.FunctionComponent<{}> = () => {

    return (
        <List divided relaxed>
            {collection1.map(essay => {
                return (
                    <List.Item key={essay.url} style={{ textAlign: "justify", padding: "15px" }}>
                        <List.Content>
                            <List.Header style={{ textAlign: "center" }}>
                                <Link to={"/esseita/" + essay.url}>
                                    <div style={{ color: "black", padding: "5px" }} >
                                        <i style={{ marginRight: "20px" }} className="align left icon" />
                                        {essay.title.toUpperCase()}
                                    </div>
                                </Link>
                            </List.Header>
                            <List.Description>{essay.description}</List.Description>
                        </List.Content>
                    </List.Item>
                );
            })}
        </List>
    )
}