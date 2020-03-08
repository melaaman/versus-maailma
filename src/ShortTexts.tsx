import React, { useEffect, useState } from 'react';
import { Dropdown, DropdownProps, Loader } from 'semantic-ui-react'
import { getAll } from "./texts";
import { ShortTextBox, ShortTextStructure } from "./ShortTextBox";

const genreOptions = [
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
        getAll().then(data => {
            setLoading(false);
            setShortTexts(data);
        });
    }, []);

    function handleTextOnChange(event: React.FormEvent<HTMLInputElement>) {
        setFilterState(event.currentTarget.value);
    }

    function handleOnChange(__e: any, data: DropdownProps) {
        setCurrentGenre(data.value as string)
    }

    function isEntryIncluded(word: string): boolean {
        const convertedWord = word.toLowerCase();
        const convertedEntry = filterState.toLowerCase();
        return convertedWord.includes(convertedEntry);
    }

    const filteredShortTextsByGenre: ShortTextStructure[] =
        currentGenre === "all" ? shortTexts : shortTexts.filter(text => text.genre === currentGenre);

    const filteredShortTextsByFilteredState: ShortTextStructure[] =
        filteredShortTextsByGenre.filter(text => isEntryIncluded(text.author) || isEntryIncluded(text.work));

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr auto", paddingBottom: "20px" }} className="ShortTexts-selection">
            <div style={{ marginRight: "5px", minWidth: "0" }} className="ui left icon input">
                <input type="text" placeholder="Etsi teosta tai tekijää..." onChange={handleTextOnChange} />
                <i className="hand point right outline icon" />
            </div>
            <Dropdown
                placeholder='Kaikki'
                fluid
                search
                selection
                options={genreOptions}
                onChange={handleOnChange}
                style={{ minWidth: "100px" }}
            />
            <div style={{ marginTop: "20px", gridColumn: "1 / span 2" }}>
                <Loader active={loading} inline='centered' style={{ marginTop: "40px" }} />
                {filteredShortTextsByFilteredState.reverse().map((text, index) => {
                    return (
                        <ShortTextBox key={index} shortText={text} />
                    )
                })}
            </div>
        </div>
    )
}