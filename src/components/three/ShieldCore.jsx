import React, { useRef, useMemo } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';

/**
 * The centerpiece interactive 3D shield component.
 */
const ShieldCore = React.memo(({ reducedMotion, scanActive, riskLevel }) => {
  const groupRef = useRef();
  const coreRef = useRef();
  const ring1Ref = useRef();
  const ring2Ref = useRef();
  const ring3Ref = useRef();
  const particlesRef = useRef();

  const colors = {
    low: '#00ff88',
    medium: '#f2b83b',
    high: '#f28c3b',
    critical: '#ff3355',
    default: '#00d4ff'
  };

  const emissiveColor = colors[riskLevel] || colors.default;
  const colorObj = useMemo(() => new THREE.Color(emissiveColor), [emissiveColor]);

  // Orbiting spheres setup
  const numOrbits = 12;
  const orbits = useMemo(() => {
    const temp = [];
    for (let i = 0; i < numOrbits; i++) {
      temp.push({
        angle: (i / numOrbits) * Math.PI * 2,
        speed: 0.5 + Math.random() * 1.5,
        radius: 2 + Math.random() * 1,
        yOffset: (Math.random() - 0.5) * 2,
      });
    }
    return temp;
  }, []);

  useFrame((state, delta) => {
    if (document.hidden || reducedMotion) return;

    const time = state.clock.getElapsedTime();
    const speedMult = scanActive ? 3 : 1;

    // Pulse core
    const scale = 0.98 + Math.abs(Math.sin(time * 2)) * 0.04;
    coreRef.current.scale.set(scale, scale, scale);

    // Rotate rings
    ring1Ref.current.rotation.x += delta * 0.2 * speedMult;
    ring1Ref.current.rotation.y += delta * 0.3 * speedMult;
    
    ring2Ref.current.rotation.y += delta * 0.15 * speedMult;
    ring2Ref.current.rotation.z += delta * 0.25 * speedMult;
    
    ring3Ref.current.rotation.x -= delta * 0.2 * speedMult;
    ring3Ref.current.rotation.z += delta * 0.1 * speedMult;

    // Mouse tracking
    const targetX = (state.pointer.x * Math.PI) / 22.5; // max +/- 8 degrees
    const targetY = (state.pointer.y * Math.PI) / 22.5;
    groupRef.current.rotation.x += (targetY - groupRef.current.rotation.x) * 0.05;
    groupRef.current.rotation.y += (targetX - groupRef.current.rotation.y) * 0.05;

    // Update orbiting particles
    if (particlesRef.current) {
      orbits.forEach((orbit, i) => {
        const child = particlesRef.current.children[i];
        if (child) {
          orbit.angle += delta * orbit.speed * speedMult;
          child.position.x = Math.cos(orbit.angle) * orbit.radius;
          child.position.z = Math.sin(orbit.angle) * orbit.radius;
          child.position.y = Math.sin(time * 2 + i) * 0.5 + orbit.yOffset;
        }
      });
    }
  });

  return (
    <group ref={groupRef}>
      {/* Core Icosahedron */}
      <mesh ref={coreRef}>
        <icosahedronGeometry args={[1.5, 1]} />
        <meshStandardMaterial 
          color="#0a1628"
          emissive={colorObj}
          emissiveIntensity={scanActive ? 2 : 0.5}
          transparent
          opacity={0.8}
          wireframe={false}
          metalness={0.8}
          roughness={0.2}
        />
      </mesh>
      
      {/* Wireframe overlay for glowing edges */}
      <mesh>
        <icosahedronGeometry args={[1.51, 1]} />
        <meshBasicMaterial 
          color={colorObj}
          wireframe
          transparent
          opacity={0.3}
        />
      </mesh>

      {/* Rings */}
      <mesh ref={ring1Ref}>
        <torusGeometry args={[2.2, 0.02, 8, 32]} />
        <meshBasicMaterial color={colorObj} transparent opacity={0.5} />
      </mesh>
      <mesh ref={ring2Ref} rotation={[Math.PI/3, 0, 0]}>
        <torusGeometry args={[2.4, 0.02, 8, 32]} />
        <meshBasicMaterial color={colorObj} transparent opacity={0.3} />
      </mesh>
      <mesh ref={ring3Ref} rotation={[0, Math.PI/4, 0]}>
        <torusGeometry args={[2.6, 0.01, 8, 32]} />
        <meshBasicMaterial color={colorObj} transparent opacity={0.2} />
      </mesh>

      {/* Orbiting Particles */}
      <group ref={particlesRef}>
        {orbits.map((_, i) => (
          <mesh key={i}>
            <sphereGeometry args={[0.05, 8, 8]} />
            <meshBasicMaterial color={colorObj} />
          </mesh>
        ))}
      </group>
    </group>
  );
});

export default ShieldCore;
