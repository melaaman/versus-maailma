import React from 'react';
import { Card } from "semantic-ui-react";
import { ShortTextStructure, Genre } from "./entities";
import './ShortTextBox.scss';

interface ShortTextBoxProps {
    shortText: ShortTextStructure;
}

export const ShortTextBox = (props: ShortTextBoxProps) => {
    const { date, title, work, author, genre, year, content, publisher } = props.shortText;

    const getIcon = (genre: Genre) => {
        switch (genre) {
            case ("literature"):
                return "book";
            case "tv":
                return "tv";
            case "movie":
                return "film";
            case "game":
                return "game";
            default:
                return "book";
        }
    };

    return (
        <div className="ShortTextBox">
            <Card style={{ width: "inherit" }} className={`active content`}>
                <Card.Content style={{ fontWeight: "bold" }} header={title.toUpperCase()} />
                <Card.Content style={{ textAlign: "justify", fontSize: "larger" }}>
                    {content}
                </Card.Content>
                <Card.Content extra>
                    <i className={`${getIcon(genre)} icon`} />
                    {author}: {work} ({publisher ? publisher + " " : ""}{year})<br />{date}
                </Card.Content>
            </Card >
        </div>
    )
}