import React, { useState, useEffect } from 'react';
import { Link, useLocation } from "react-router-dom";

type AppPage = "home" | "esseita" | "lyhyesti";

export const AppNavigation = () => {
    const location = useLocation();
    const [currentPage, setCurrentPage] = useState(location.pathname.slice(1));

    useEffect(() => {
        const path = location.pathname === "/" ? "home" : location.pathname.slice(1);
        setCurrentPage(path);
    }, [location]);

    const menuItemClassName = (page: AppPage) => `item grey ${currentPage.includes(page) ? "active" : ""}`;

    return (
        <div style={{ justifyContent: "center", fontSize: "small" }} className="ui secondary pointing menu">
            <Link to="/" className={menuItemClassName("home")}>
                Etusivu
            </Link>
            <Link to="/esseita" className={menuItemClassName("esseita")}>
                Esseitä
            </Link>
            <Link to="/lyhyesti" className={menuItemClassName("lyhyesti")}>
                Lyhyesti
            </Link>
        </div>
    )
}