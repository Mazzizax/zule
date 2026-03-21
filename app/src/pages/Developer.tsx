import { useEffect } from 'react';

export default function Developer() {
  useEffect(() => {
    window.location.href = 'https://mazzizax.org/contact';
  }, []);

  return null;
}
