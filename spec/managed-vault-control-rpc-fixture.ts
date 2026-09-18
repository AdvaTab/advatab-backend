import type {
  EffectiveEntitlement,
  InitializeManagedVaultRequest,
  InitializeManagedVaultResult,
  ManagedCredential,
  ManagedDevice,
  ManagedPasskeyAssertion,
  ManagedRecoveryEnvelope,
  ManagedVaultControlRpc,
  RecoverManagedDeviceRequest,
  RecoverManagedDeviceResult,
  VerifyManagedPasskeyRequest,
  VerifyManagedPasskeyResult,
  StoreManagedRecoveryGenerationRequest,
  StoreManagedRecoveryGenerationResult,
  HasManagedRecoveryGenerationRequest,
  HasManagedRecoveryGenerationResult,
  VerifyManagedPasskeyInput,
  ConfirmManagedRecoveryGenerationInput,
  ConfirmManagedRecoveryGenerationResult,
  StoreManagedRecoveryGenerationInput,
  RecoverManagedDeviceInput,
  SetEffectiveEntitlementRequest,
  SetEffectiveEntitlementResult,
} from '../src/managed-control';

/**
 * Copy this type contract into customer-management when configuring its
 * external Durable Object namespace binding. The backend remains the sole
 * owner of the class and its SQLite migrations.
 */
export type ManagedVaultNamespace = DurableObjectNamespace<ManagedVaultControlRpc>;

export interface ManagedVaultExternalBinding {
  name: 'VAULTS';
  className: 'VaultDurableObject';
  scriptName: string;
}

export const managedVaultExternalBinding: ManagedVaultExternalBinding = {
  name: 'VAULTS',
  className: 'VaultDurableObject',
  scriptName: '<backend-worker-script-name>',
};

export type {
  EffectiveEntitlement,
  InitializeManagedVaultRequest,
  InitializeManagedVaultResult,
  ManagedCredential,
  ManagedDevice,
  ManagedPasskeyAssertion,
  ManagedRecoveryEnvelope,
  ManagedVaultControlRpc,
  RecoverManagedDeviceRequest,
  RecoverManagedDeviceResult,
  VerifyManagedPasskeyRequest,
  VerifyManagedPasskeyResult,
  StoreManagedRecoveryGenerationRequest,
  StoreManagedRecoveryGenerationResult,
  HasManagedRecoveryGenerationRequest,
  HasManagedRecoveryGenerationResult,
  VerifyManagedPasskeyInput,
  ConfirmManagedRecoveryGenerationInput,
  ConfirmManagedRecoveryGenerationResult,
  StoreManagedRecoveryGenerationInput,
  RecoverManagedDeviceInput,
  SetEffectiveEntitlementRequest,
  SetEffectiveEntitlementResult,
};
