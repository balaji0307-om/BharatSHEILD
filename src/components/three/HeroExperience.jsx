import React, { useRef, useState } from 'react';
import { useFrame } from '@react-three/fiber';
import * as THREE from 'three';
import ShieldCore from './ShieldCore';
import ThreatParticles from './ThreatParticles';
import IndiaNetwork from './IndiaNetwork';

/**
 * Main landing 3D scene orchestrator with intro animations.
 */
const HeroExperience = ({ 
  onIntroComplete, 
  reducedMotion, 
  scanActive, 
  riskLevel = 'default',
  skipIntro = false 
}) => {
  const groupRef = useRef();
  const shieldRef = useRef();
  const particlesRef = useRef();
  const networkRef = useRef();
  
  const [introDone, setIntroDone] = useState(skipIntro || reducedMotion);
  const timeRef = useRef(0);
  
  useFrame((state, delta) => {
    if (document.hidden || introDone) return;
    
    timeRef.current += delta;
    const t = timeRef.current;
    
    // 0-2s: particles fade in
    if (particlesRef.current) {
      const pOpacity = THREE.MathUtils.clamp(t / 2, 0, 1);
      particlesRef.current.scale.setScalar(THREE.MathUtils.lerp(0.001, 1, pOpacity));
    }
    
    // 2-4s: India network fades in
    if (networkRef.current) {
      const nOpacity = THREE.MathUtils.clamp((t - 2) / 2, 0, 1);
      networkRef.current.scale.setScalar(THREE.MathUtils.lerp(0.001, 1, nOpacity));
    }
    
    // 4-5.5s: Shield materializes
    if (shieldRef.current) {
      if (t > 4) {
        const sProgress = THREE.MathUtils.clamp((t - 4) / 1.5, 0, 1);
        const ease = 1 - Math.pow(1 - sProgress, 3);
        shieldRef.current.scale.setScalar(ease);
      } else {
        shieldRef.current.scale.setScalar(0.001);
      }
    }
    
    // After 7s
    if (t > 7) {
      setIntroDone(true);
      if (onIntroComplete) onIntroComplete();
    }
  });

  return (
    <group ref={groupRef}>
      <group ref={particlesRef} scale={introDone ? 1 : 0.001}>
        <ThreatParticles reducedMotion={reducedMotion} threatLevel={30} />
      </group>
      
      <group ref={networkRef} scale={introDone ? 1 : 0.001}>
        <IndiaNetwork reducedMotion={reducedMotion} />
      </group>
      
      <group ref={shieldRef} scale={introDone ? 1 : 0.001}>
        <ShieldCore 
          reducedMotion={reducedMotion} 
          scanActive={scanActive} 
          riskLevel={riskLevel} 
        />
      </group>
    </group>
  );
};

export default HeroExperience;
