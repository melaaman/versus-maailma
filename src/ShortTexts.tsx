import React, { useEffect, useState, FormEvent } from 'react';
import { Dropdown, DropdownProps, Loader } from 'semantic-ui-react';
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
    let initialAccordionState: boolean[] = [];

    const [shortTexts, setShortTexts] = useState(initialShortTextState);
    const [currentGenre, setCurrentGenre] = useState("all");
    const [filterState, setFilterState] = useState("");
    const [loading, setLoading] = useState(true);
    const [accordionState, setAccordionState] = useState(initialAccordionState);

    useEffect(() => {
        let isSubscribed = true;
        getAll().then((data: ShortTextStructure[]) => {
            if (isSubscribed) {
                setLoading(false);
                setShortTexts(data);
                setAccordionState(Array(data.length).fill(false));
            }
        });
        return () => {
            isSubscribed = false;
        }
    }, []);

    function handleTextOnChange(event: FormEvent<HTMLInputElement>) {
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

    function handleOnClick(itemIndex: number) {
        let newAccordionState: boolean[] = [];
        accordionState.forEach((item, index) => {
            if (index === itemIndex) {
                item = !item;
            }
            newAccordionState.push(item);
        });
        setAccordionState(newAccordionState);
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
                        <ShortTextBox key={index} shortText={text} isActive={accordionState[index] ? accordionState[index] : false} onClick={() => handleOnClick(index)} />
                    );
                })}
            </div>
        </div>
    )
}