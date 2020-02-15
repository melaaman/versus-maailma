import React, { useState } from 'react';
import { Essay } from "./Essay";
import { OnFiction } from "./essays/OnFiction";
import { TextAccordion } from "./TextAccordion";

const collection1 = [
    OnFiction
];


export const Essays = () => {
    const essaysInitialState: { [key: string]: boolean } = {};
    const [essaysState, setEssaysState] = useState(essaysInitialState);

    function handleOnClick(essayTitle: string) {
        const newEssaysState = { ...essaysState, [essayTitle]: !essaysState[essayTitle] };
        setEssaysState(newEssaysState);
    };

    const className = (essayTitle: string): string => `${essaysState[essayTitle] ? "active" : ""}`;

    return (
        <TextAccordion>
            {collection1.map((essay, index) => {
                const isAlign = index % 2 !== 0;
                return (
                    <Essay key={essay.title} handleOnClick={() => handleOnClick(essay.title)} isEven={isAlign} className={className(essay.title)} essay={essay} />
                );
            })}
        </TextAccordion>
    )
}