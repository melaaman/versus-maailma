import React from 'react';
import { Card, Accordion, Icon } from "semantic-ui-react";
import { ShortTextStructure, Genre } from "./entities";
import './ShortTextBox.scss';

interface ShortTextBoxProps {
    shortText: ShortTextStructure;
    isActive: boolean;
    onClick: () => void;
}

export const ShortTextBox = (props: ShortTextBoxProps) => {
    const { date, title, work, author, genre, year, content, publisher } = props.shortText;

    const getGenreIcon = (genre: Genre) => {
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

    const contentStyle = {
        textAlign: "justify",
        fontSize: "larger",
        padding: "15px"
    }

    return (
        <div className="ShortTextBox">
            <Card style={{ width: "inherit" }} className={`active content`}>
                <Accordion>
                    <Accordion.Title active={props.isActive} style={{ fontWeight: "bold", paddingTop: "10px" }} onClick={props.onClick}>
                        <Icon name='dropdown' />
                        {title.toUpperCase()}
                    </Accordion.Title>
                    <Accordion.Content active={!props.isActive} style={{ ...contentStyle, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                        {content}
                    </Accordion.Content>
                    <Accordion.Content active={props.isActive} style={contentStyle}>
                        {content}
                    </Accordion.Content>
                </Accordion>
                <Card.Content extra>
                    <i className={`${getGenreIcon(genre)} icon`} />
                    {author}: {work} ({publisher ? publisher + " " : ""}{year})<br />{date}
                </Card.Content>
            </Card >
        </div>
    )
}