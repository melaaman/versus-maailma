import React from 'react';
import { Link } from "react-router-dom";
import { List } from "semantic-ui-react";
import { collection1 } from "./entities";
import './Essays.scss';

export const Essays = () => {

    return (
        <div className="Essays">
            <List divided relaxed>
                {collection1.map(essay => {
                    return (
                        <List.Item key={essay.url}>
                            <List.Content>
                                <List.Header className="Essays-header">
                                    <Link to={"/esseita/" + essay.url}>
                                        <div className="Essays-header-link">
                                            <i style={{ marginRight: "20px" }} className="align left icon" />
                                            {essay.title.toUpperCase()}
                                        </div>
                                    </Link>
                                </List.Header>
                                <List.Description className="Essays-description">
                                    {essay.description}
                                </List.Description>
                            </List.Content>
                        </List.Item>
                    );
                })}
            </List>
        </div>
    )
}