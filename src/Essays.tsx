import React, { useState } from 'react';
import { Essay } from "./Essay";
import { OnFiction } from "./essays/OnFiction";
import { TextAccordion } from "./TextAccordion";
import { History } from 'history';
import { useLocation } from "react-router-dom";

const collection1 = [
    OnFiction
];

interface EssaysProps {
    history: History;
}


export const Essays = (props: EssaysProps) => {
    const currentPath = useLocation();

    const getInitialEssaysState = (): { [key: string]: boolean } => {
        const path = currentPath.pathname;
        const currentEssay = collection1.find(item => path.includes(item.url));
        const currentEssayTitle = !!currentEssay ? currentEssay.title : "";
        return !currentEssayTitle ? {} : { [currentEssayTitle]: true };
    }

    const [essaysState, setEssaysState] = useState(getInitialEssaysState);

    function handleOnClick(essayTitle: string, essayUrl: string) {
        const newEssaysState = { ...essaysState, [essayTitle]: !essaysState[essayTitle] };
        const url = newEssaysState[essayTitle] ? essayUrl : "";
        setEssaysState(newEssaysState);
        props.history.push(`/essays/${url}`);
    };

    const className = (essayTitle: string): string => `${essaysState[essayTitle] ? "active" : ""}`;

    return (
        <TextAccordion>
            {collection1.map((essay, index) => {
                const isAlign = index % 2 !== 0;
                return (
                    <Essay key={essay.title} handleOnClick={() => handleOnClick(essay.title, essay.url)} isEven={isAlign} className={className(essay.title)} essay={essay} />
                );
            })}
        </TextAccordion>
    )
}