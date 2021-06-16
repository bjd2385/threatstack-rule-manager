import './SquareButtons.css';

const SquareButtons = (props) => {
  const classes = "square-button " + props.buttonclass

  return (
    <div>
      <button type="submit" className={classes} />
    </div>
  );
}

export default SquareButtons;