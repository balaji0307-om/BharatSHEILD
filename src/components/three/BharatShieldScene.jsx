import React, { Suspense, useEffect, useState } from 'react';
import { Canvas } from '@react-three/fiber';

/**
 * Main Canvas wrapper for the BharatSHIELD 3D experience.
 */
const BharatShieldScene = ({ children, className, style }) => {
  const [isPaused, setIsPaused] = useState(false);

  useEffect(() => {
    const handleVisibilityChange = () => {
      setIsPaused(document.hidden);
    };
    
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, []);

  return (
    <div 
      className={className} 
      style={{
        position: 'absolute',
        inset: 0,
        pointerEvents: 'none',
        ...style
      }}
    >
      <Canvas
        dpr={[1, 1.5]}
        camera={{ position: [0, 0, 8], fov: 45 }}
        frameloop={isPaused ? 'never' : 'always'}
        gl={{ powerPreference: 'high-performance', antialias: false }}
      >
        <ambientLight intensity={0.3} />
        <pointLight position={[5, 5, 5]} intensity={0.8} color="#00d4ff" />
        
        <Suspense fallback={null}>
          {children}
        </Suspense>
      </Canvas>
    </div>
  );
};

export default BharatShieldScene;
