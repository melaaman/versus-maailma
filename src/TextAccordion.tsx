import React from 'react';


export const TextAccordion: React.FunctionComponent<{}> = (props) => {
    return (
        <div className="ui accordion">
            {props.children}
        </div>
    );
};
