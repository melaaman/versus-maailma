import React from 'react';
// import { ShortTextBox } from "./ShortTextBox";
import { Dropdown, DropdownProps } from 'semantic-ui-react'

const genreOptions = [
    { key: 'all', value: 'all', text: 'Kaikki' },
    { key: 'books', value: 'books', text: 'Kirjat' },
    { key: 'movies', value: 'movies', text: 'Elokuvat' },
    { key: 'series', value: 'series', text: 'Tv-sarjat' },
    { key: 'games', value: 'games', text: 'Pelit' }
]

export const ShortTexts = () => {

    function handleOnChange(__e: any, data: DropdownProps) {
        console.log(data.value)
    }

    return (
        <div style={{ display: "grid", gridTemplateColumns: "1fr auto", paddingBottom: "20px" }} className="ShortTexts-selection">
            <div style={{ marginRight: "5px", minWidth: "0" }} className="ui left icon input">
                <input type="text" placeholder="Etsi tekstejä..." />
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
            <div style={{ marginTop: "20px" }}>
                (TBA)
            </div>
            {/* <ShortTextBox /> */}
        </div>
    )
}