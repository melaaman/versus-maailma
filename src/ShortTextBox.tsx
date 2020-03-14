import React from 'react';
import { Card } from "semantic-ui-react";

type Genre = "literature" | "movie" | "tv" | "game";

export interface ShortTextStructure {
    date: string;
    title: string;
    author: string;
    work: string;
    genre: Genre;
    content: string;
    year: string,
    publisher?: string;
}

interface ShortTextBoxProps {
    shortText: ShortTextStructure;
}

export const ShortTextBox = (props: ShortTextBoxProps) => {
    const { date, title, work, author, genre, year, content, publisher } = props.shortText;

    const getIcon = (genre: Genre) => {
        switch (genre) {
            case ("literature"):
                return "book";
            default:
                return "book";
        }
    };

    return (
        <Card style={{
            fontSize: "smaller",
            width: "inherit",
            letterSpacing: "0"
        }} className={`active content`}>
            <Card.Content style={{ fontWeight: "bold" }} header={title.toUpperCase()} />
            <Card.Content style={{ textAlign: "justify", fontSize: "larger" }}>{content}</Card.Content>
            <Card.Content extra>
                <i className={`${getIcon(genre)} icon`} />{author}: {work} ({publisher} {year})<br />{date}
            </Card.Content>
        </Card >
    )
}