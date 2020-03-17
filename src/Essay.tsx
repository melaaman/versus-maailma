import React from 'react';
import { EssayStructure } from "./entities";
import './Essay.scss';

interface EssayProps {
    essay: EssayStructure;
}

export const Essay = (props: EssayProps) => {
    const { essay } = props

    return (
        <div className="Essay">
            <div className="Essay-title" >
                {essay.title.toUpperCase()}
            </div>
            <div className="Essay-content">
                {essay.content}
            </div>
        </div>
    );
};