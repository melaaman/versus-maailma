import React, { useState } from 'react';
import { Link } from "react-router-dom";

type AppPage = "home" | "essays" | "shortly";

export const AppNavigation = () => {
    const pathName = window.location.pathname;
    const slicedPathName: string = pathName.length > 1 ? pathName.slice(1) : "home";

    const [currentPage, setCurrentPage] = useState(slicedPathName);

    function handleOnClick(page: AppPage) {
        setCurrentPage(page);
    }

    const menuItemClassName = (page: AppPage) => `item grey ${currentPage === page ? "active" : ""}`;

    return (
        <div style={{ justifyContent: "center", fontSize: "small" }} className="ui secondary pointing menu">
            <Link to="/" className={menuItemClassName("home")} onClick={() => handleOnClick("home")}>
                Etusivu
        </Link>
            <Link to="/essays" className={menuItemClassName("essays")} onClick={() => handleOnClick("essays")}>
                Esseitä
        </Link>
            <Link to="/shortly" className={menuItemClassName("shortly")} onClick={() => handleOnClick("shortly")}>
                Lyhyesti
        </Link>
        </div>
    )
}