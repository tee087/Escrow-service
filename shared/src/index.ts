export const dealStatuses = ['PENDING','ACCEPTED','FUNDED','IN_PROGRESS','DELIVERED','COMPLETED','DISPUTED','CANCELLED','REFUNDED'] as const;
export type DealStatus = typeof dealStatuses[number];
export const canTransition = (from: DealStatus, to: DealStatus) => ({ PENDING:['ACCEPTED','CANCELLED'], ACCEPTED:['FUNDED','CANCELLED'], FUNDED:['IN_PROGRESS','DISPUTED'], IN_PROGRESS:['DELIVERED','DISPUTED'], DELIVERED:['COMPLETED','DISPUTED'], COMPLETED:[], DISPUTED:['REFUNDED','COMPLETED'], CANCELLED:[], REFUNDED:[] }[from] as string[]).includes(to);
