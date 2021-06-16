import { useEffect } from "react";

import './Version.css';

function Version(props) {
  const apiURL = props.apiUrl;

  useEffect(() => {
    fetch(apiURL + '/version')
      .then(res => res.json())
      .then(
      )
  }, [])

  return (
    <p>
      v0.1.0
    </p>
  )
}

export default Version;