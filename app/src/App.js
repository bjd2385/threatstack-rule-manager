import React from 'react';
import './App.css';

const apiURL = 'http://localhost:8000';

function Version() {
  const [error, setError] = React.useState(null);
  const [isLoaded, setIsLoaded] = React.useState(false);
  const [item, setItem] = React.useState([]);

  React.useEffect(() => {
    fetch(apiURL + '/version')
      .then(res => res.json())
      .then(
        (result) => {
          this.setState({
            isLoaded: true,
            item: result.item
          });
        },
        (error) => {
          this.setState({
            isLoaded: true,
            error
          });
        }
      )
  }, [])

  if (error) {
    return <div>Error: {error.message}</div>;
  } else if (!isLoaded) {
    return <div>Loading...</div>;
  } else {
    return (
      <p>
        {item.version}
      </p>
    );
  }
}

function App() {
  return (
    <div className="App">
      <header className="App-header">
        Threat Stack Rule Manager {Version()}
      </header>
    </div>
  );
}

export default App;
