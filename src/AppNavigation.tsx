import React, { useState, useEffect } from 'react';
import { Link, useLocation } from "react-router-dom";

type AppPage = "home" | "essays" | "shortly";

export const AppNavigation = () => {
    const pathName = useLocation();

    const [currentPage, setCurrentPage] = useState(pathName.pathname.slice(1));

    useEffect(() => {
        const path = pathName.pathname === "/" ? "home" : pathName.pathname.slice(1);
        setCurrentPage(path);
    }, [pathName]);

    const menuItemClassName = (page: AppPage) => `item grey ${currentPage.includes(page) ? "active" : ""}`;

    return (
        <div style={{ justifyContent: "center", fontSize: "small" }} className="ui secondary pointing menu">
            <Link to="/" className={menuItemClassName("home")}>
                Etusivu
            </Link>
            <Link to="/essays" className={menuItemClassName("essays")}>
                Esseitä
            </Link>
            <Link to="/shortly" className={menuItemClassName("shortly")}>
                Lyhyesti
            </Link>
        </div>
    )
}