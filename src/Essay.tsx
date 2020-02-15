import React from 'react';

export interface EssayStructure {
    title: string;
    content: JSX.Element;
}

interface EssayProps {
    essay: EssayStructure;
    className: string;
    isEven: boolean;
    handleOnClick: (essayTitle: string) => void;
}

export const Essay = (props: EssayProps) => {
    const { className, isEven, handleOnClick, essay } = props;

    const textAlign = isEven ? "end" : "start";
    const fontWeight = className ? "bold" : "normal";

    return (
        <div style={{ textAlign, marginBottom: "40px" }} className="Essay">
            <div style={{ fontWeight }} className={`${className} title`} onClick={() => handleOnClick(essay.title)} >
                <i style={{ marginRight: "20px" }} className="align left icon" />
                {essay.title.toUpperCase()}
            </div>
            <div style={{ letterSpacing: "0", textAlign: "justify" }} className={`${className} content`} >
                {essay.content}
            </div>
        </div>
    );
};