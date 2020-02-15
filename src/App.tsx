import React from 'react';
import { Container } from 'semantic-ui-react';
import { AppContainer } from "./AppContainer";
import {
  BrowserRouter as Router
} from "react-router-dom";
import { AppNavigation } from "./AppNavigation";
import './App.css';

const App = () => {
  return (
    <Container>
      <Router>
        <div className="App">
          <div className="App-header">
            versus maailma
          </div>
          <AppNavigation />
          <div className="App-content">
            <AppContainer />
          </div>
          <div className="App-footer">
            Erika Laamanen
          </div>
        </div>
      </Router>
    </Container>
  );
}

export default App;
