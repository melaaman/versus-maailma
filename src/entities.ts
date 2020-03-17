import { OnFiction } from "./essays/OnFiction";
import { Lectio } from "./essays/Lectio";

export interface EssayStructure {
    title: string;
    url: string;
    description: JSX.Element,
    content: JSX.Element;
}

export interface ShortTextStructure {
    date: string;
    title: string;
    author: string;
    work: string;
    genre: Genre;
    content: string;
    year: string,
    publisher?: string;
}

export type Genre = "literature" | "movie" | "tv" | "game";


export const collection1 = [
    OnFiction,
    Lectio
];

