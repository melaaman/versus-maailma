import React from 'react';
import { Card, Icon } from "semantic-ui-react";

export const ShortTextBox = () => {

    return (
        <Card style={{
            fontSize: "smaller",
            width: "inherit"
        }} className={`active content`}>
            <Card.Content header='OTSIKKO' />
            <Card.Content description={"sisältö"} />
            <Card.Content extra>
                <Icon name='book' />Olli Jalonen: Merenpeitto <br />Otava 2019
            </Card.Content>
        </Card >
    )
}