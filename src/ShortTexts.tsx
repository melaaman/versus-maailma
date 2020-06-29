import React, { useEffect, useState } from 'react';
import { Dropdown, DropdownProps, Loader } from 'semantic-ui-react'
import { getAll } from "./texts";
import { ShortTextBox } from "./ShortTextBox";
import { ShortTextStructure } from "./entities";
import './ShortTexts.scss';

const dropdownOptions = [
    { key: "all", value: "all", text: "Kaikki" },
    { key: "literature", value: "literature", text: "Kirjat" },
    { key: "movie", value: "movie", text: "Elokuvat" },
    { key: "tv", value: "tv", text: "Tv-sarjat" },
    { key: "game", value: "game", text: "Pelit" }
]

export const ShortTexts = () => {
    let initialShortTextState: ShortTextStructure[] = [];

    const [shortTexts, setShortTexts] = useState(initialShortTextState);
    const [currentGenre, setCurrentGenre] = useState("all");
    const [filterState, setFilterState] = useState("");
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let isSubscribed = true;
        getAll().then(data => {
            if (isSubscribed) {
                setLoading(false);
                setShortTexts(data);
            }
        });
        return () => {
            isSubscribed = false;
        }
    }, []);

    function handleTextOnChange(event: React.FormEvent<HTMLInputElement>) {
        setFilterState(event.currentTarget.value);
    }

    function handleDropDownOnChange(__e: any, data: DropdownProps) {
        setCurrentGenre(data.value as string)
    }

    function isKeywordIncluded(word: string): boolean {
        const targetWord = word.toLowerCase();
        const keyword = filterState.toLowerCase();
        return targetWord.includes(keyword);
    }

    function getFilteredShortTexts(): ShortTextStructure[] {
        const filteredByGenre = currentGenre === "all" ? shortTexts : shortTexts.filter(text => text.genre === currentGenre);
        return filteredByGenre.filter(text => isKeywordIncluded(text.author) || isKeywordIncluded(text.work));
    };

    return (
        <div className="ShortTexts">
            <div className="ui left icon input">
                <input type="text" placeholder="Etsi teosta tai tekijää..." onChange={handleTextOnChange} />
                <i className="hand point right outline icon" />
            </div>
            <Dropdown
                placeholder='Kaikki'
                fluid
                search
                selection
                options={dropdownOptions}
                onChange={handleDropDownOnChange}
                style={{ minWidth: "100px" }}
            />
            <div className="ShortTexts-content">
                <Loader active={loading} inline='centered' style={{ marginTop: "40px" }} />
                {getFilteredShortTexts().reverse().map((text, index) => {
                    return (
                        <ShortTextBox key={index} shortText={text} />
                    );
                })}
            </div>
        </div>
    )
}