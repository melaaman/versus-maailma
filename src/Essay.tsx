import React from 'react';

export interface EssayStructure {
    title: string;
    url: string;
    description: JSX.Element,
    content: JSX.Element;
}

interface EssayProps {
    essay: EssayStructure;
}

export const Essay = (props: EssayProps) => {
    const { essay } = props

    return (
        <div className="Essay">
            <div style={{ fontWeight: "bold", marginBottom: "15px" }} >
                {essay.title.toUpperCase()}
            </div>
            <div style={{ letterSpacing: "0", textAlign: "justify" }} >
                {essay.content}
            </div>
        </div>
    );
};