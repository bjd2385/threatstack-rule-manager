import './App.css';

import Version from './components/Version';

function App() {
  const apiURL = 'http://localhost:8000';

  return (
    <div className="App">
      <header className="App-header">
        Threat Stack Rule Manager
      </header>
      <Version apiUrl={apiURL} />
    </div>
  );
}

export default App;
