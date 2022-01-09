/*
 *      WARNING:
 *      I'm not a Windows expert nor am I a professional reverse engineer. Most of the pseudo code 
 *      is pure theory after reading other functions and understanding their flow. This is my attempt 
 *      to comprehend some of the section creation logic in Windows. If you happen to spot anything 
 *      wrong, please feel free to inform me. 
 */

// Taken from jxy-s' "Process Herpaderping" post
// https://jxy-s.github.io/herpaderping/res/DivingDeeper.html
struct CREATE_SECTION_PACKET
{
    ULONG Flags;
    DWORD Unknown04;
    POBJECT_ATTRIBUTES InputObjectAttributes;
    ULONG AllocateAttributes;
    ULONG InputAllocationAttributes;
    UCHAR InputSectionSignatureLevel;
    BYTE Unknown19;
    WORD Unknown1A;
    ULONG InputSectionPageProtection;
    ULONG PageProtectionMask;
    DWORD Unknown24;
    HANDLE InputFileHandle;
    PFILE_OBJECT InputFileObject;
    PFILE_OBJECT FileObject;
    CONTROL_AREA *SectionControlArea;
    KPROCESSOR_MODE InputPreviousMode;
    BYTE Unknown49[67];
    DWORD Unknown8C;
    SECTION *SectionObject;
    PLARGE_INTEGER MaximumSize;
    PACCESS_TOKEN InputToken;
    DWORD InputSessionId;
    DWORD UnknownAC;
    MI_PARTITION *Partition;
    PIRP TopLevelIrp;
    BYTE UnknownC0;
    BYTE UnknownC1[3];
    DWORD UnknownC4;
};

bool __fastcall MiControlAreaExemptFromCrossPartitionCharges(_CONTROL_AREA *controlArea)
{
    // If it cannot be used cross-partition, it must be free of charges.
    if (controlArea.u1.Flags.NoCrossPartitionAccess)
    {
        return true;
    }

    // No FILE_OBJECT?
    if (!controlArea.FilePointer)
    {
        // Maybe is a system image?
        if (controlArea.u2.e2.SystemImage)
        {
            return true;
        }
    }

    return false;
}

// The returned int is an error code.
// This is rather speculation after reading the functions that use this function, but...
// 0 -> STATUS_CROSS_PARTITION_VIOLATION
// 1 -> There's no cross-partition charge
// 2 -> There's cross-partition charge
int __fastcall MiControlAreaRequiresCharge(_CONTROL_AREA *controlArea, unsigned char allocation_context)
{
    _MI_PARTITION *partition;
    _EPROCESS *process;

    process = (_EPROCESS *)KeGetCurrentThread()->ApcState.Process;

    // Check if we are exempt of cross-partition charges
    if (MiControlAreaExemptFromCrossPartitionCharges(controlArea))
    {
        return 1;
    }

    // If we are not exempt then check if our allocation have any "special" requirements...
    if (allocation_context > 1)
    {

        // 2 -> Per-session section
        // Does our partition depend on the session? For example using SEC_BASED
        if (allocation_context == 2)
        {
            partition = *(_MI_PARTITION **)(partitions_table + process->Session.Vm.Instance.PartitionId * 8);
        }

        else /* 3 or 4 */
        {
            // 3 -> Data section in system space?
            // 4 -> Image section in system space?
            // Will it be in the system space? (kernel)
            // Also, on x86 only this partition exists.
            partition = &MiSystemPartition;
        }
    }
    else /* 0 or 1 */
    {
        // 0 -> Data section in user space?
        // 1 -> Image section in user space?
        // If it does not need special requirements, i.e., it is a "normal" section we should just use
        // the process partition.
        partition = *(_MI_PARTITION **)(partitions_table + process->Vm.Instance.PartitionId * 8);
    }

    // If we are not cross-partition our partition should be the same as in the control area.
    if (partition == *(_MI_PARTITION **)(partitions_table + controlArea.u1.Flags.PartitionId * 8))
    {
        return 1;
    }

    // If the partition is not the same as in the control area, then it should be a cross-partition access.
    // In that case, `NoCrossPartitionAccess` should be 0.
    if (!controlArea.u1.Flags.NoCrossPartitionAccess)
    {
        return 2;
    }

    // Unknown check. Considering the prior speculations about `allocation_context`, presumably checks if 
    // it's an image.
    if (allocation_context == 1 || allocation_context == 4)
    {
        return 2;
    }

    // Before returning 0 it increments a global DWORD that appears to be the subsection's view count.

    // If the partition was not the same as the one referenced in the control area, and `NoCrossPartitionAccess` 
    // is active, either the `allocation_context` was wrong or the control area partition is not correct.
    // STATUS_CROSS_PARTITION_VIOLATION
    return 0;
}

NTSTATUS __fastcall MiReferenceControlArea(CREATE_SECTION_PACKET *createSectionPacket,
                                           CONTROL_AREA *tempControlArea,
                                           CONTROL_AREA **newControlArea)
{
    CONTROL_AREA *controlArea;
    FILE_OBJECT *fileObject;

    fileObject = createSectionPacket->FileObject;

    // Is it an image?
    if (createSectionPacket->AllocateAttributes & SEC_IMAGE)
    {
        controlArea = fileObject->SectionObjectPointer->ImageSectionObject;
    }
    else
    {
        controlArea = fileObject->SectionObjectPointer->DataSectionObject;
    }

    // Is it already in memory?
    // When DataSectionObject or ImageSectionObject are NULL it means that **currently** the file is not
    // in memory.
    if (!controlArea)
    {
        // If the file is not in memory then `MiCreateImageOrDataSection` should continue with the `CONTROL_AREA`
        // that is being created.
        *newControlArea = tempControlArea;

        return STATUS_SUCCESS;
    }

    // Check if `createSectionPacket` partition is valid.
    status = MiValidateControlAreaPartition(createSectionPacket, controlArea);

    if (status == STATUS_OPERATION_IN_PROGRESS)
    {
        // Release file if not valid partition and stop section creation.
        FsRtlReleaseFile(fileObject);
        tempControlArea.u.Flags.BeingCreated = false;

        return status;
    }

    // Ensure our control area is not being deleted or created.
    if (!controlArea.u.Flags.BeingDeleted && controlArea.u.Flags.BeingCreated)
    {
        if (createSectionPacket->AllocateAttributes & SEC_IMAGE)
        {
            // Unknown allocation attribute. Appears to specify if the image is going to be allocated in the
            // system (kernel) space.
            // Set by `MiCreateSectionForDriver`.
            if (createSectionPacket->InputAllocationAttributes & 0x00100000)
            {
                // This can only be two values: 2 or 3.
                // It will be 2 if image is allocated with `SEC_BASED`, 3 if not.
                unsigned char allocation_context = (((createSectionPacket->InputAllocationAttributes & SEC_BASED) == 0) | 2);

                if (MiControlAreaRequiresCharge(controlArea, allocation_context) == 0)
                {
                    return STATUS_CROSS_PARTITION_VIOLATION;
                }
            }
        }

        // Add new reference to the `CONTROL_AREA`, we'll share it for both sections.
        MiReferenceActiveControlArea(createSectionPacket, controlArea);
        *newControlArea = controlArea;
        return STATUS_SUCCESS;
    }

    // Something happened...
    *newControlArea = NULL;
    return STATUS_RETRY;
}

NTSTATUS __fastcall MiCreateImageOrDataSection(CREATE_SECTION_PACKET *createSectionPacket)
{
    NTSTATUS status;
    FILE_OBJECT *fileObject;
    CONTROL_AREA tempControlArea;
    CONTROL_AREA *newControlArea;
    CONTROL_AREA *newSectionControlArea;

    // Unknown allocation attribute. Probably similar to `SEC_LARGE_PAGES` with something else 
    // (maybe `MEM_RESERVE`). If the section needs to be created using large pages then the physical 
    // memory needs to be allocated immediately upon section creation.
    if ((createSectionPacket->AllocateAttributes & 0x80020000) == 0)
    {
        fileObject = createSectionPacket->InputFileObject;

        // No FILE_OBJECT was provided
        if (!fileObject)
        {
            // If no `FILE_OBJECT` was provided then get it
            status = ObReferenceObjectByHandle(createSectionPacket->InputFileHandle,
                                               MmMakeFileAccess[createSectionPacket->PageProtectionMask & 7],
                                               IoFileObjectType,
                                               createSectionPacket->InputPreviousMode,
                                               &fileObject,
                                               NULL);

            // We can't continue without a file...
            if (!NT_SUCCESS(status))
            {
                return status;
            }
        }

        // No section created for this file?
        if (!fileObject->SectionObjectPointer)
        {
            return STATUS_INVALID_FILE_FOR_SECTION;
        }

        // As we are going to use this `FILE_OBJECT` we need to increment its reference count.
        ObfReferenceObject(fileObject);
        createSectionPacket->FileObject = fileObject;

        // Is our image allowed to run?
        if (createSectionPacket->AllocationAttributes & SEC_IMAGE)
        {
            if ((createSectionPacket->Flags & 0x400) && !IoAllowExecution(fileObject))
            {
                return STATUS_ACCESS_DENIED;
            }
        }

        tempControlArea.u.Flags.BeingCreated = true;
        tempControlArea.FilePointer.Value = fileObject;
        newControlArea = NULL;

        // Take correct control area.
        status = MiReferenceControlArea(createSectionPacket, tempControlArea, &newControlArea);
        if (!NT_SUCCESS(status))
        {
            return status
        }

        createSectionPacket->SectionControlArea = newControlArea;

        // If our control area is still being created, it means that our file was not in memory.
        if (newControlArea->u.Flags.BeingCreated)
        {
            newSectionControlArea = NULL;
            status = MiCreateNewSection(createSectionPacket, &newSectionControlArea);
            if (NT_SUCCESS(status))
            {
                // Zero-out our `SECTION_OBJECT_POINTERS` struct
                LONG controlAreaLock = MiZeroSectionObjectPointer(fileObject, tempControlArea,
                                                                  createSectionPacket->AllocateAttributes);

                if (newSectionControlArea)
                {
                    newControlArea = newSectionControlArea;
                    createSectionPacket->SectionControlArea = *newSectionControlArea;
                }

                // Zero-out our `SECTION_OBJECT_POINTERS` struct
                LONG controlAreaLock = MiZeroSectionObjectPointer(fileObject, tempControlArea,
                                                                  createSectionPacket->AllocateAttributes);

                // It's the same as our temp control area?
                if (newSectionControlArea == tempControlArea)
                {
                    ObfDereferenceObject(fileObject);
                    fileObject = ObFastReplaceObject(newSectionControlArea->FilePointer, 0);
                }

                // If not same then increment the control area count.
                else
                {
                    _InterlockedIncrement64(&MiGetControlAreaPartition(newControlArea)->Segments.FsControlAreaCount);
                    MiDereferenceControlAreaBySection(newControlArea, 1);
                }

                MiReleaseControlAreaWaiters(controlAreaLock);
            }

            return status;
        }

        // If our new control area does not contain `BeingCreated`, it means our file was in memory. 
        // Let's just use the existing control area
        else
        {
            status = MiShareExistingControlArea(createSectionPacket);
            if (!NT_SUCCESS(status))
            {
                MiDereferenceFailedControlArea(createSectionPacket);
            }
            return status;
        }
    }

    return STATUS_INVALID_PARAMETER_6;
}
