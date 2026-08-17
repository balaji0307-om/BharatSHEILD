import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

/**
 * Dashboard threat visualization globe.
 */
const ThreatGlobe = React.memo(({ reducedMotion, threatCount = 0 }) => {
  const globeRef = useRef();
  const particlesRef = useRef();

  const particleCount = Math.min(threatCount, 10); // cap at 10 to keep it clean

  const particles = useMemo(() => {
    return Array(particleCount).fill().map(() => ({
      angleX: Math.random() * Math.PI * 2,
      angleY: Math.random() * Math.PI * 2,
      speed: 0.5 + Math.random() * 1.5,
      radius: 2.1
    }));
  }, [particleCount]);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion) return;
    
    if (globeRef.current) {
      globeRef.current.rotation.y += delta * 0.1;
      globeRef.current.rotation.x += delta * 0.05;
    }
    
    if (particlesRef.current) {
      particles.forEach((p, i) => {
        p.angleX += delta * p.speed;
        p.angleY += delta * (p.speed * 0.5);
        
        const child = particlesRef.current.children[i];
        if (child) {
          child.position.x = Math.cos(p.angleX) * Math.sin(p.angleY) * p.radius;
          child.position.y = Math.sin(p.angleX) * Math.sin(p.angleY) * p.radius;
          child.position.z = Math.cos(p.angleY) * p.radius;
        }
      });
    }
  });

  return (
    <group>
      <mesh ref={globeRef}>
        <icosahedronGeometry args={[2, 2]} />
        <meshBasicMaterial 
          color="#00d4ff" 
          wireframe 
          transparent 
          opacity={0.3} 
        />
        {/* Inner core */}
        <mesh>
          <icosahedronGeometry args={[1.9, 1]} />
          <meshBasicMaterial color="#0a1628" transparent opacity={0.8} />
        </mesh>
      </mesh>
      
      <group ref={particlesRef}>
        {particles.map((_, i) => (
          <mesh key={i}>
            <sphereGeometry args={[0.08, 8, 8]} />
            <meshBasicMaterial color="#ff3355" />
          </mesh>
        ))}
      </group>
    </group>
  );
});

export default ThreatGlobe;
