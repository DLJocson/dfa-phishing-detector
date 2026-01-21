import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import DarkModeToggle from './DarkModeToggle';

test('renders with moon icon by default', () => {
  const { getByText } = render(<DarkModeToggle />);
  const iconElement = getByText('🌙');
  expect(iconElement).toBeInTheDocument();
});

test('toggles to sun icon on click', () => {
  const { getByText } = render(<DarkModeToggle />);
  const buttonElement = getByText('🌙').closest('button');

  fireEvent.click(buttonElement);

  const iconElement = getByText('☀️');
  expect(iconElement).toBeInTheDocument();
});

test('toggles back to moon icon on second click', () => {
  const { getByText } = render(<DarkModeToggle />);
  const buttonElement = getByText('🌙').closest('button');

  fireEvent.click(buttonElement); 
  fireEvent.click(buttonElement);

  const iconElement = getByText('🌙');
  expect(iconElement).toBeInTheDocument();
});

test('applies dark-mode class to body on toggle', () => {
  const { getByText } = render(<DarkModeToggle />);
  const buttonElement = getByText('🌙').closest('button');

  fireEvent.click(buttonElement);

  expect(document.body.classList.contains('dark-mode')).toBe(true);
});

test('removes dark-mode class from body on second toggle', () => {
  const { getByText } = render(<DarkModeToggle />);
  const buttonElement = getByText('🌙').closest('button');

  fireEvent.click(buttonElement);
  fireEvent.click(buttonElement);

  expect(document.body.classList.contains('dark-mode')).toBe(false);
});
