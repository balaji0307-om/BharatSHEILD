import { useState, useEffect } from 'react';

/**
 * Hook to detect device capabilities (low-end device, mobile device).
 * @returns {{ isLowEnd: boolean, isMobile: boolean }}
 */
export default function useDeviceCapability() {
  const [capability, setCapability] = useState({ isLowEnd: false, isMobile: false });

  useEffect(() => {
    const checkCapability = () => {
      const isMobile = window.innerWidth < 768 || navigator.maxTouchPoints > 0;
      const hardwareConcurrency = navigator.hardwareConcurrency || 4;
      const isLowEnd = hardwareConcurrency < 4;
      
      setCapability({ isLowEnd, isMobile });
    };

    checkCapability();
    window.addEventListener('resize', checkCapability);
    return () => window.removeEventListener('resize', checkCapability);
  }, []);

  return capability;
}
