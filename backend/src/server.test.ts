import { describe, expect, it } from 'vitest';
import { canTransition } from '../../shared/src/index.js';
describe('escrow transitions', () => { it('permits the standard completion path', () => { expect(canTransition('PENDING','ACCEPTED')).toBe(true); expect(canTransition('ACCEPTED','FUNDED')).toBe(true); expect(canTransition('DELIVERED','COMPLETED')).toBe(true); }); it('rejects skipped payment verification', () => expect(canTransition('PENDING','FUNDED')).toBe(false)); });
