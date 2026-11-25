// Apply the repository's recovered names, comments, formal variables, and data
// types to an imported E64 WS ELF.
//
// This is an additive, repeatable annotation layer for
// HEM-HSG-HMI-S01 V01.16-24. It is not the original vendor source.
//
// Headless usage:
//   -scriptPath tools/ghidra
//   -postScript ApplyE64RecoveredAnnotations.java elf-offset=0x10000
//
// The retained imports present the PIE ELFs at +0x10000. The resolver tries
// ELF+offset first and falls back to the ELF address for other import layouts.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

public class ApplyE64RecoveredAnnotations extends GhidraScript {
    private long elfOffset = 0x10000L;
    private int foundFunctions;
    private int missingFunctions;
    private int namedParameters;
    private int createdParameters;
    private int typedParameters;
    private int createdLabels;
    private int skippedFunctions;

    private DataType commandDefType;
    private DataType recoveredBrewInputType;
    private DataType recoveredUartEnvelopeType;
    private DataType gbsSamplePointType;
    private DataType algorithmV1StateType;
    private DataType algorithmV2StateType;
    private DataType algorithmV3StateType;
    private DataType algorithmV4StateType;
    private DataType gbsServiceStateType;

    private static final class FunctionSpec {
        final long elf;
        final String name;
        final String comment;
        final String[] parameters;

        FunctionSpec(long elf, String name, String comment, String... parameters) {
            this.elf = elf;
            this.name = name;
            this.comment = comment;
            this.parameters = parameters;
        }
    }

    private static FunctionSpec f(long elf, String name, String comment,
                                  String... parameters) {
        return new FunctionSpec(elf, name, comment, parameters);
    }

    private static final FunctionSpec[] FUNCTIONS = {
        // Dispatcher, WebSocket bridge, and complete direct registry.
        f(0x003fb298L, "e64_CommandRegistry_constructor", "13 direct records and 39 GrinderAction variants; see docs/API_REGISTRY.md.", "this"),
        f(0x003fa25cL, "e64_JsonConnector_handleMessage", "Canonical actions use type=GrinderAction and data.actionType=<suffix>. Source-like model: src/recovered/json_connector_reconstruction.cpp.", "this", "message"),
        f(0x003ee9d8L, "e64_JsonConnector_handleFoundMessage", "Callback lookup/dispatch boundary; exact Qt temporaries and failure body remain unresolved.", "this", "message", "commandDef"),
        f(0x003ee910L, "e64_JsonConnector_validateTokenWithDef", "Token-required gate: nonempty role and unexpired record; no per-command role comparison recovered.", "this", "message", "commandDef"),
        f(0x0044dd30L, "e64_WebSocketConnector_validateToken", "WSS token validation; token file is consumed and in-memory expiry is refreshed for roughly 300 seconds.", "this", "token"),
        f(0x0044e544L, "e64_WebSocketConnector_textMessageReceived", "ping=true is handled locally; other text is parsed and dispatched.", "this", "text"),
        f(0x0044f478L, "e64_WebSocketConnector_onNewConnection", "WSS connection setup and URL-token bridge; close behavior is runtime-only.", "this", "connection"),

        f(0x003f12b8L, "e64_cmd_RequestDriverConfig", "Direct registry callback."),
        f(0x003f1910L, "e64_cmd_RequestDriverState", "Direct read-only driver-state callback."),
        f(0x003f1f5cL, "e64_cmd_RequestLogMessages", "Direct development-only log callback."),
        f(0x003f25b8L, "e64_cmd_RequestAdcConfig", "Direct development-only ADC callback."),
        f(0x003f4124L, "e64_cmd_RequestConfigManagerSettings", "Direct development-only settings callback."),
        f(0x003f4778L, "e64_cmd_RequestNachineInfo", "Direct callback; binary spelling preserved."),
        f(0x003f2c08L, "e64_cmd_RequestOnboarding", "Special RequestOnboardingResult response without recovered refId."),
        f(0x003f31ecL, "e64_cmd_WifiStaConfig", "Direct WiFi station configuration callback."),
        f(0x003f37d0L, "e64_cmd_WifiConfigChanged", "Direct WiFi-config-changed callback."),
        f(0x003f988cL, "e64_cmd_UpdateDriverConfig", "Direct development-only maintenance callback."),
        f(0x003f7c20L, "e64_cmd_UpdateCpuConfig", "Direct development-only callback; payload ignored and result failure-valued."),
        f(0x003f4dd0L, "e64_cmd_CustomSignal1", "Direct custom signal callback; payload ignored."),
        f(0x003f5440L, "e64_cmd_CustomSignal2", "Direct custom signal callback; payload ignored."),

        // All action callback addresses; the suffix is data.actionType, not a
        // top-level GrinderAction<suffix> wire type.
        f(0x003f6098L, "e64_action_Stop", "GrinderAction suffix Stop."),
        f(0x003f6190L, "e64_action_StartGrindManual", "Hazardous grind action."),
        f(0x003f7d00L, "e64_action_StartGrindGbw", "Hazardous GBW action; targetWeightGr is numeric."),
        f(0x003f7f4cL, "e64_action_StartGrindGbt", "Hazardous GBT action; grindTimeSec is numeric."),
        f(0x003f6288L, "e64_action_StartCalibration", "Hazardous calibration action."),
        f(0x003f6380L, "e64_action_StartTara", "Hazardous tare action."),
        f(0x003f6478L, "e64_action_SaveLog", "GrinderAction suffix SaveLog."),
        f(0x003f6570L, "e64_action_ResetLog", "GrinderAction suffix ResetLog."),
        f(0x003f819cL, "e64_action_SetFanTemperatureCtrlEnabled", "Fan temperature-control action."),
        f(0x003f6668L, "e64_action_CalibrateFan1", "Hazardous fan calibration action."),
        f(0x003f6760L, "e64_action_CalibrateFan2", "Hazardous fan calibration action."),
        f(0x003f6858L, "e64_action_ToggleBacklightPower", "Backlight power action."),
        f(0x003f89f8L, "e64_action_SetBacklightBrightness", "Backlight brightness action; full range unresolved."),
        f(0x003f8538L, "e64_action_SetFan1Duty", "Hazardous fan duty action; low-level clamp is 0..100."),
        f(0x003f8798L, "e64_action_SetFan2Duty", "Hazardous fan duty action; low-level clamp is 0..100."),
        f(0x003f8c58L, "e64_action_SetAgsaTargetDdValue", "Hazardous AGSA/DD target action; driver admission guards apply."),
        f(0x003f7020L, "e64_action_StopAgsa", "Hazardous AGSA stop action."),
        f(0x003f7130L, "e64_action_CalibrateDdSensor", "Hazardous DD-sensor calibration action."),
        f(0x003f6f28L, "e64_action_ResetDriverConfig", "Token-required maintenance action; not development-only in the registry."),
        f(0x003f8eb0L, "e64_action_SetLanguage", "Language action."),
        f(0x003f94ecL, "e64_action_StartEnduranceTest", "Hazardous endurance-test action."),
        f(0x003f7b10L, "e64_action_StopEnduranceTest", "Hazardous endurance-test stop action."),
        f(0x003faba0L, "e64_action_SetSetupWizardState", "Hazardous setup-state action; NotRun/Disabled/Completed are recovered values."),
        f(0x003f9cacL, "e64_action_AddBrewEvent", "Event injection action; reads grindUuid, machineName, groupHead, doseIndex, validity, brewTimeMs, brewWeightMg; internal source label is web_simu."),
        f(0x003f6988L, "e64_action_EspFlashApp", "Hazardous ESP flash action; archive provenance boundary is documented."),
        f(0x003f6a94L, "e64_action_EspEraseFlash", "Hazardous ESP erase action."),
        f(0x003f6c10L, "e64_action_EspReset", "Hazardous ESP reset action; token-required and not development-only."),
        f(0x003f6d18L, "e64_action_NozzleLightRunStandby", "Nozzle-light action."),
        f(0x003f6e20L, "e64_action_NozzleLightStop", "Nozzle-light stop action."),
        f(0x003f7270L, "e64_action_RcTopLeftClick", "Hazardous remote-control input injection."),
        f(0x003f7384L, "e64_action_RcTopLeftLong", "Hazardous remote-control input injection."),
        f(0x003f7498L, "e64_action_RcTopLeftPress", "Hazardous remote-control input injection."),
        f(0x003f75acL, "e64_action_RcTopLeftRelease", "Hazardous remote-control input injection."),
        f(0x003f76c0L, "e64_action_RcBottomLeftClick", "Hazardous remote-control input injection."),
        f(0x003f77d4L, "e64_action_RcRotaryClick", "Hazardous remote-control input injection."),
        f(0x003f78e8L, "e64_action_RcRotaryLong", "Hazardous remote-control input injection."),
        f(0x003f79fcL, "e64_action_RcRotaryDouble", "Hazardous remote-control input injection."),
        f(0x003f9198L, "e64_action_RcRotary", "Hazardous rotary tick injection."),
        f(0x003f3d30L, "e64_action_GbsCreateReport", "Special response type GbsCreateReport, not GrinderActionResult."),

        // GBS arithmetic and DD efficiency.
        f(0x00328168L, "e64_AlgorithmV1_constructor", "V1 defaults: capacity 4, central width 2, quantum 0.2um, hysteresis 0.16um.", "this", "initialDdDum"),
        f(0x00328530L, "e64_AlgorithmV1_adjust", "V1 median/cubic correction/quantizer/commit gate; see src/recovered/gbs_algorithms.cpp.", "this", "actualBrewDurationMs", "targetBrewDurationMs", "estimatedDdDum", "setpointDdDum", "toleranceMs"),
        f(0x0032ac18L, "e64_AlgorithmV2_adjust", "V2 six-point inverse regression, sign guard, 10/90 blend and lround.", "this", "actualBrewDurationMs", "targetBrewDurationMs", "estimatedDdDum", "setpointDdDum", "toleranceMs"),
        f(0x0032fc80L, "e64_AlgorithmV3_adjust", "V3 one-history far/mid/near phases and DD-times-brew filter.", "this", "actualBrewDurationMs", "targetBrewDurationMs", "estimatedDdDum", "setpointDdDum", "toleranceMs"),
        f(0x003365b8L, "e64_AlgorithmV4_adjust", "V4 strict <3s lock-in, <=5s mid boundary, >5s far reset.", "this", "actualBrewDurationMs", "targetBrewDurationMs", "estimatedDdDum", "setpointDdDum", "toleranceMs"),
        f(0x0032aa58L, "e64_AlgorithmV2_constructor", "V2 default constructor; one six-sample regression deque.", "this"),
        f(0x0032f1f8L, "e64_AlgorithmV3_constructor", "V3 defaults: hold=2, far=0.0, mid=0.5, near=1.0, filter=0.5.", "this", "holdCyclesSetting", "farFactor", "midFactor", "nearFactor", "filterRetention"),
        f(0x00335030L, "e64_AlgorithmV4_constructor", "V4 defaults: hold=2, far=0.0, mid=0.5, near=1.0, filter=0.5.", "this", "holdCyclesSetting", "farFactor", "midFactor", "nearFactor", "filterRetention"),
        f(0x00339d28L, "e64_LinearRegression_inversePredict", "Inverse regression: x=setpoint um, y=actual seconds; slope guard -2/-0.5.", "history", "targetDurationSec"),
        f(0x0044abb8L, "e64_HystereticQuantization_constructor", "Hysteretic quantizer constructor; recovered call uses factor 0.8, quantum 0.2, and previous value.", "this", "hysteresisFactor", "quantumUm", "previousUm"),
        f(0x0044abccL, "e64_HystereticQuantization_quantize", "Inclusive +/-0.16um hold and C round-away behavior.", "this", "valueUm"),
        f(0x00338924L, "e64_DdEffMeasurement_adjust", "DD-efficiency adjustment resumes a coroutine sequence; ordinary inputs ignored."),
        f(0x00338ec8L, "e64_DdEffMeasurementPrivate_run", "DD-efficiency coroutine factory."),
        f(0x00338678L, "e64_DdEffMeasurement_coroutineActor", "Six repeated requests at initial, initial-200, initial+200 deci-um.", "frame"),
        f(0x00338f40L, "e64_DdEffMeasurement_constructor", "DdEff initializes the measurement sequence from an initial DD.", "this", "initialDdDum"),

        // GBS persistence, selection, service gates, and reusable predictors.
        f(0x003292ecL, "e64_AlgorithmV1_deserialize", "V1 state deserializer; exact JSON keys are in GBS_TRACK_C_EXACT_REVERSAL.md.", "this", "json"),
        f(0x003277d0L, "e64_AlgorithmV1_debug", "V1 diagnostic-data accessor.", "this"),
        f(0x003277dcL, "e64_AlgorithmV1_serialize", "V1 serializer; emits type/version/history, last brew duration, coarseness, and quantized output; adjacent last-result literal is not in the recovered normal pairs.", "this"),
        f(0x003277d8L, "e64_AlgorithmV1_setDebug", "V1 debug flag setter.", "this", "enabled", "reset"),
        f(0x0032b8acL, "e64_AlgorithmV2_deserialize", "V2 state deserializer.", "this", "json"),
        f(0x00329f20L, "e64_AlgorithmV2_debug", "V2 diagnostic-data accessor.", "this"),
        f(0x00329f2cL, "e64_AlgorithmV2_serialize", "V2 serializer; history samples use effectiveGrindSizeUm and brewDurationSec.", "this"),
        f(0x00329f28L, "e64_AlgorithmV2_setDebug", "V2 debug flag setter.", "this", "enabled", "reset"),
        f(0x0033277cL, "e64_AlgorithmV3_deserialize", "V3 state deserializer; restores history, filters, factors, thresholds, and hold counters.", "this", "json"),
        f(0x0032c4e8L, "e64_AlgorithmV3_serialize", "V3 serializer; exact key spellings are documented in GBS_TRACK_C_EXACT_REVERSAL.md.", "this"),
        f(0x0032c428L, "e64_AlgorithmV3_debug", "V3 diagnostic-data accessor.", "this"),
        f(0x0032c430L, "e64_AlgorithmV3_parameterEntryCount", "V3 parameter inspection count; binary spelling is paramterEntryCount.", "this"),
        f(0x0032c438L, "e64_AlgorithmV3_parameterEntryAt", "V3 parameter inspection entry; binary spelling is paramterEntryAt.", "this", "index"),
        f(0x0032e620L, "e64_AlgorithmV3_parameterNameList", "V3 parameter-name list accessor.", "this"),
        f(0x0032d64cL, "e64_AlgorithmV3_farThresholdSec", "V3 far threshold is nearThreshold+3 when keep-medium is enabled, otherwise 5 seconds.", "this"),
        f(0x0032d670L, "e64_AlgorithmV3_processThresholdSecChanged", "V3 reprocesses threshold configuration.", "this"),
        f(0x0032de48L, "e64_AlgorithmV3_processKeepMediumIntervalChanged", "V3 reprocesses keep-medium-width configuration.", "this"),
        f(0x00333b70L, "e64_AlgorithmV4_debug", "V4 diagnostic-data accessor.", "this"),
        f(0x00333b7cL, "e64_AlgorithmV4_serialize", "V4 serializer; exact key spellings are documented in GBS_TRACK_C_EXACT_REVERSAL.md.", "this"),
        f(0x003359d4L, "e64_AlgorithmV4_deserialize", "V4 state deserializer.", "this", "json"),
        f(0x00339070L, "e64_DdEffMeasurement_deserialize", "DdEff state deserializer; restores initialCoarsenessDum.", "this", "json"),
        f(0x00338a80L, "e64_DdEffMeasurement_serialize", "DdEff serializer.", "this"),
        f(0x00338674L, "e64_DdEffMeasurement_setDebug", "DdEff debug flag setter.", "this", "enabled", "reset"),
        f(0x00326c68L, "e64_AbstractAlgorithm_instanceId", "Algorithm instance-id accessor.", "this"),
        f(0x00326c70L, "e64_AbstractAlgorithm_setInstanceId", "Algorithm instance-id setter used by state recovery.", "this", "instanceId"),
        f(0x00326c78L, "e64_AbstractAlgorithm_parameterNameList", "Base algorithm parameter-name list accessor.", "this"),
        f(0x00326c98L, "e64_AbstractAlgorithm_parameterEntryCount", "Base algorithm parameter inspection count; binary spelling is paramterEntryCount.", "this"),
        f(0x00326ca0L, "e64_AbstractAlgorithm_parameterEntryAt", "Base algorithm parameter inspection entry; binary spelling is paramterEntryAt.", "this", "index"),
        f(0x00326cacL, "e64_AbstractAlgorithm_debugData", "Base algorithm diagnostic-data accessor.", "this"),
        f(0x00326cc4L, "e64_AbstractAlgorithm_setDoubleParameter", "Base algorithm double parameter setter.", "this", "name", "value"),
        f(0x00326f1cL, "e64_AbstractAlgorithm_clearParameter", "Base algorithm optional-parameter clear path.", "this", "name"),
        f(0x0032757cL, "e64_AbstractAlgorithm_setBoolParameter", "Base algorithm boolean parameter setter.", "this", "name", "value"),
        f(0x00339460L, "e64_EffectiveDdPrediction_constructor", "Effective-DD predictor constructor; state is 24 bytes in GbsService.", "this", "residueEffectiveDdUm"),
        f(0x00339494L, "e64_EffectiveDdPrediction_setResidue", "Sets effective-DD residue in micrometers.", "this", "residueEffectiveDdUm"),
        f(0x003394b4L, "e64_EffectiveDdPrediction_setGrindEffectiveDd", "Sets the effective DD output in the predictor.", "this", "grindEffectiveDdDum"),
        f(0x00339ac4L, "e64_EffectiveDdPrediction_addGrind", "Updates effective DD using DD*0.1, duration*0.001, ln(2), and time constant 1.85.", "this", "grindDdDum", "grindDurationMs"),
        f(0x00339824L, "e64_EffectiveDdPrediction_fromJson", "Restores version-1 effective-DD JSON.", "this", "json"),
        f(0x003394f0L, "e64_EffectiveDdPrediction_toJson", "Serializes {version:1,grindSizeUm:<double>}.", "this"),

        f(0x0034f0bcL, "e64_GbsService_constructor", "GBS service dependency graph; field layout is installed as /E64Recovered/GbsServiceState.", "this", "brewEventStorage", "recipeProvider", "gbsStateStorage", "patchableConfig", "debugFlags", "parent"),
        f(0x0034397cL, "e64_GbsService_initAlgorithm", "Case-sensitive selector: GbS1, GbS2, GbS3, GbS4, DdEff; unknown falls back to V1.", "this", "initialDdUm", "algorithmName"),
        f(0x0034aa58L, "e64_GbsService_processGrindResult", "Updates/stores EffectiveDdPrediction before purge/success/recipe/eligibility gates.", "this", "grind", "recipe", "successful"),
        f(0x00345528L, "e64_GbsService_brewEventValidForAdjustment", "Exact validity accessor reads event+0x30.", "this", "event"),
        f(0x0034d548L, "e64_GbsService_receivedBrewEvent", "Accepted brew-event path after grouphead, pending-match, duration, and validity gates.", "this", "event", "gbsMode"),
        f(0x0034f0a8L, "e64_GbsService_receivedStandardBrewEvent", "StandardGbs dispatch; first checks grouphead selection then pending match.", "this", "event"),
        f(0x0034835cL, "e64_GbsService_brewEventCompliesWithGroupheadSelection", "Grouphead-selection admission check.", "this", "event"),
        f(0x00345018L, "e64_GbsService_matchBrewEventToPending", "Pending match order: grind ID, exact flow/e/a discriminator, then dose/recipe discriminator.", "this", "event"),
        f(0x0034cd7cL, "e64_GbsService_recoverOrInitAlgorithm", "Cache lookup then state-blob recovery; failed/empty state initializes a fresh algorithm.", "this", "algorithmKey", "recipe"),
        f(0x003433a8L, "e64_GbsService_gbsAlgoStateToAlgorithm", "Deserializes algorithm state into an algorithm object.", "this", "state", "algorithmName"),
        f(0x00343f0cL, "e64_GbsService_recipeStateToJson", "Serializes initializationValueMym, coursenessDeciMym, and gbsMode.", "this", "recipeState"),
        f(0x00348a68L, "e64_GbsService_recipeStateFromJson", "Restores recipe GBS state with signed-32-bit validation.", "this", "json"),
        f(0x003456fcL, "e64_GbsService_effectiveDdPredictionLoad", "Loads persisted effective DD predictor state.", "this"),
        f(0x00345a04L, "e64_GbsService_effectiveDdPredictionStore", "Stores persisted effective DD predictor state.", "this"),
        f(0x00349adcL, "e64_GbsService_collectGrindDebugData", "Collects algorithm diagnostics into a JSON object.", "this", "recipeIndex", "output"),
        f(0x00345674L, "e64_GbsService_gbsAlgoStateLoad", "Loads serialized algorithm state and instance ID.", "this", "algorithmKey", "instanceId"),
        f(0x00345658L, "e64_GbsService_gbsAlgoStateStore", "Stores serialized algorithm state and instance ID.", "this", "algorithmKey", "state", "instanceId"),
        f(0x003456ecL, "e64_GbsService_gbsAlgoStateStoreDeleted", "Deletes persisted algorithm state for a recipe/algorithm key.", "this", "recipeIndex"),
        f(0x00347810L, "e64_GbsService_resetState", "Resets GBS runtime state and pending workflow.", "this"),
        f(0x0034731cL, "e64_GbsService_setGbsState", "Writes state values Idle=0, Progress=1, Success=2, Failed=3.", "this", "state", "emitSignal"),
        f(0x0034761cL, "e64_GbsService_timeoutCancelEvent", "Cancels pending event workflow after timeout.", "this"),
        f(0x00344740L, "e64_GbsService_storePendingBrewInfo", "Persists pending brew/grind correlation state.", "this"),
        f(0x00349da8L, "e64_GbsService_restorePendingBrewInfo", "Restores pending brew/grind correlation state.", "this"),
        f(0x00349388L, "e64_GbsService_initializationValue", "Reads per-recipe GBS initialization DD.", "this", "recipeIndex"),
        f(0x003494a8L, "e64_GbsService_standardGbsInitializationValue", "Reads standard GBS initialization DD.", "this", "recipeIndex"),
        f(0x003492e0L, "e64_GbsService_recipeGbsMode", "Reads recipe GBS mode.", "this", "recipeIndex", "syncTag"),
        f(0x003490d4L, "e64_GbsService_recipeGbsModeCpp", "C++ recipe GBS-mode accessor.", "this", "recipeIndex"),
        f(0x00349160L, "e64_GbsService_recipeHasAnyGbs", "Checks whether a recipe has any GBS mode.", "this", "recipeIndex", "syncTag"),
        f(0x003491d4L, "e64_GbsService_recipeHasStandardGbs", "Checks standard GBS mode.", "this", "recipeIndex", "syncTag"),
        f(0x00349258L, "e64_GbsService_recipeHasManualGbs", "Checks manual GBS mode.", "this", "recipeIndex", "syncTag"),
        f(0x0034c0ecL, "e64_GbsService_applySpecialStateToRecipe", "Applies special-state outcome to a recipe.", "this", "recipeIndex", "gbsMode"),
        f(0x00347a20L, "e64_GbsService_handleRecipeGbsDisabled", "Disables/reset path for a recipe whose GBS mode is removed.", "this", "recipeIndex"),
        f(0x00149350L, "e64_GbsService_brewEventDroppedDueToDuration", "Failure signal for matched events at or below 10000 ms.", "this", "event"),
        f(0x00342dfcL, "e64_GbsService_setAlgo3ThresholdSec", "Sets Algorithm-3 near threshold configuration.", "this", "thresholdSec"),
        f(0x003430f8L, "e64_GbsService_setAlgo3KeepMediumInterval", "Sets Algorithm-3 medium-interval policy.", "this", "enabled"),
        f(0x00342d94L, "e64_GbsService_applyAllAlgo3ThresholdSec", "Reapplies Algorithm-3 threshold to cached objects.", "this"),
        f(0x00343090L, "e64_GbsService_applyAllAlgo3KeepMediumInterval", "Reapplies Algorithm-3 medium policy to cached objects.", "this"),
        f(0x0034236cL, "e64_GbsService_applyOneAlgo3ThresholdSec", "Applies Algorithm-3 threshold to one algorithm object.", "this", "algorithm"),
        f(0x003428a8L, "e64_GbsService_applyOneAlgo3KeepMediumInterval", "Applies Algorithm-3 medium policy to one algorithm object.", "this", "algorithm"),
        f(0x00342358L, "e64_GbsService_setPreventAgsaBrewtimeRangeMs", "Sets prevent-AGSA brew-time range; getter exposes 0..10000 ms.", "this", "rangeMs"),
        f(0x00342350L, "e64_GbsService_preventAgsaBrewtimeRangeMs", "Reads runtime prevent-AGSA brew-time range.", "this"),
        f(0x00348064L, "e64_GbsService_groupheadFromBrewEvent", "Maps brew-event grouphead metadata to configured selection.", "event"),
        f(0x00345530L, "e64_GbsService_groupheadSelectionToConfigString", "Formats grouphead selection configuration value.", "selection"),
        f(0x00346b24L, "e64_GbsService_brewEventToString", "Diagnostic formatter for brew-event fields.", "event"),

        // Dial-in and grind-time helpers are adjacent to the GBS service and
        // feed it initial values; they are not adaptive V1-V4 updates.
        f(0x002c4b34L, "e64_DialInWizardHelper_proposedDdCalculate", "Model/roast one-row dial-in formula; output pointer receives proposed DD.", "this", "weightMg", "roastDegreeIndex", "modelType", "outputDdUm"),
        f(0x002c62c0L, "e64_DialInWizardHelper_proposedDd", "Public dial-in wrapper around model/roast selection.", "this", "weightMg", "modelType"),
        f(0x002c4ac8L, "e64_DialInWizardHelper_modelTypeIsValid", "Model enum accepts E64=1, E65=2, E80=3.", "modelType"),
        f(0x002c4adcL, "e64_DialInWizardHelper_modelTypeToString", "Model enum string conversion.", "modelType"),
        f(0x00351754L, "e64_GrindTimeAdjustmentService_grindVelocity", "Exact velocity curve: 1.0 + 0.0022017*x.", "value"),
        f(0x00351770L, "e64_GrindTimeAdjustmentService_adjustTime", "ByWeight-only time adjustment using grind velocity ratio and lround.", "this", "recipe", "targetDdUm"),
        f(0x00351850L, "e64_GrindTimeAdjustmentService_adjustedTimeOrZero", "Returns zero when no optional time adjustment exists.", "this", "recipe", "targetDdUm"),

        // Motor, AGSA, fan, ADC, NTC, and CPU-temperature boundaries.
        f(0x0022d3e8L, "e64_MotorControl_startMotor", "Rejects duplicate start/absent CPU driver, resets timer, starts sequence, asserts grind GPIO."),
        f(0x0022d5a0L, "e64_MotorControl_stopMotor", "Clears software isRunning; immediate physical deassertion unresolved."),
        f(0x0022d700L, "e64_MotorControl_disableMotor", "Resets timer and disables sequencer when driver exists."),
        f(0x001a48f0L, "e64_AgsaController_startMotor", "AGSA sensor/config/controller/hopper/fault guards then direction inversion and PWM.", "this", "requestedDirection"),
        f(0x001a5998L, "e64_AgsaController_setMotorDirection", "Direction GPIO mapping; physical finer/coarser meaning unresolved.", "this", "requestedDirection"),
        f(0x001a63f4L, "e64_AgsaController_detectBlockage", "Hall delta nonzero resets blockage counter; zero increments while moving."),
        f(0x001a6660L, "e64_AgsaController_processTimeoutDriveToDd", "Timeout state/log path; direct motor stop is not proven here."),
        f(0x001a713cL, "e64_AgsaController_startTimeout", "Timeout = 10000ms + round(abs(distance/(speedField*10))*1000*1.5)."),
        f(0x001a81b0L, "e64_AgsaController_updatePwm", "Numeric states 0..8; settling and hard 40-tick ceiling documented."),
        f(0x002274ccL, "e64_FanDriver_setPwmDuty", "Fan duty clamps to 0..100; disabled returns; zero clears tacho state.", "this", "requestedDuty"),
        f(0x00227ef8L, "e64_FanDriver_setControlledRpm", "Controlled-RPM path; curve documented in DRIVER_LIMITS.md."),
        f(0x00228048L, "e64_FanDriver_processTachoFrequency", "RPM=round(frequencyHz*30); >50RPM error moves duty one; >5 bad cycles fails."),
        f(0x002286a4L, "e64_FanDriver_processTemperature", "Temperature dispatch; curve and overheat policy unresolved."),
        f(0x0020fd50L, "e64_AdcVoltageInDriver_processDmaValue", "ADC circular signed running average or offset/scale path."),
        f(0x00210244L, "e64_AdcVoltageInDriver_processPollingTimeout", "ADC timeout path; invalid sentinel near -999."),
        f(0x002108c8L, "e64_AdcVoltageInDriver_processFailedTimeout", "ADC failure comparison uses sampleCount/2 versus failure counter."),
        f(0x0021b114L, "e64_CpuTemperature_adcToDegreesC", "30+(raw-cal1)*80/(cal2-cal1).", "raw", "calibration1", "calibration2"),
        f(0x0021b170L, "e64_CpuTemperature_processTimeoutUpdate", "Validity requires received samples > bufferLength/2."),
        f(0x0021b268L, "e64_CpuTemperature_processDmaAdcValue", "CPU temperature DMA sample path."),
        f(0x0021123cL, "e64_AgsaCurrent_convertAdcVoltageMv", "Identity current conversion: current_mA=input_mV.", "inputMv"),
        f(0x00211240L, "e64_AgsaCurrent_processAdcVoltageMv", "800mA default threshold; clear below threshold-50mA."),
        f(0x00211310L, "e64_AgsaCurrent_setThreshold", "Writes supplied current threshold."),
        f(0x0022e740L, "e64_NtcDriver_processAdcVoltageMv", "Inclusive -60..150C acceptance and recovered hysteresis transitions."),
        f(0x0022e588L, "e64_NtcDriver_setOverheatHysteresis", "NTC rising/falling hysteresis setter."),

        // Host ESP transport and SQLite resource anchors.
        f(0x0018f40L, "e64_serial_drv_read", "Host ESP serial read path; see ESP_PROTOCOL.md.", "handle", "bytesRead"),
        f(0x0019178L, "e64_transport_pserial_composeTlv", "Builds 14-byte ctrlResp/ctrlEvnt envelope.", "outBuffer", "payload", "payloadLength"),
        f(0x00191dcL, "e64_transport_pserial_parseTlv", "Parses 14-byte envelope; no checksum/signature recovered.", "buffer", "payloadLength"),
        f(0x0019444L, "e64_transport_pserial_open", "Opens host ESP serial transport."),
        f(0x00193d4L, "e64_transport_pserial_close", "Closes host ESP serial transport."),
        f(0x00194f4L, "e64_transport_pserial_send", "Sends host ESP frame; 16-bit boundary is a static concern.", "buffer", "payloadLength"),
        f(0x00196b0L, "e64_transport_pserial_read", "Reads host ESP frame.", "payloadLength"),
        f(0x0045523cL, "e64_qInitResources_Sqlite", "Qt SQLite resource registration; exact SQL is decoded by the extraction tool."),
    };

    @Override
    public void run() throws Exception {
        parseArguments();
        println("E64 recovered annotation pass: program=" + currentProgram.getName()
            + " elfOffset=0x" + Long.toHexString(elfOffset));
        installRecoveredDataTypes();
        for (FunctionSpec spec : FUNCTIONS) {
            annotateFunction(spec);
        }
        installDataLabels();
        println("ANNOTATION_SUMMARY functions=" + foundFunctions
            + " missing=" + missingFunctions
            + " parameters=" + namedParameters
            + " createdParameters=" + createdParameters
            + " typedParameters=" + typedParameters
            + " labels=" + createdLabels
            + " skipped=" + skippedFunctions);
    }

    private void parseArguments() {
        for (String argument : getScriptArgs()) {
            if (argument.startsWith("elf-offset=")) {
                elfOffset = Long.decode(argument.substring("elf-offset=".length()));
            }
        }
    }

    private Address resolveElf(long elfAddress) {
        Address shifted = toAddr(elfAddress + elfOffset);
        if (hasProgramContent(shifted)) {
            return shifted;
        }
        return toAddr(elfAddress);
    }

    private boolean hasProgramContent(Address address) {
        return currentProgram.getMemory().contains(address)
            || currentProgram.getFunctionManager().getFunctionAt(address) != null
            || currentProgram.getFunctionManager().getFunctionContaining(address) != null;
    }

    private void annotateFunction(FunctionSpec spec) {
        if (!appliesToCurrentProgram(spec)) {
            skippedFunctions++;
            return;
        }
        Address address;
        try {
            address = resolveElf(spec.elf);
        }
        catch (Exception exc) {
            println("MISSING_ADDRESS 0x" + Long.toHexString(spec.elf) + " " + spec.name);
            missingFunctions++;
            return;
        }

        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function == null) {
            createSafeLabel(address, spec.name + "_entry");
            println("NO_FUNCTION " + address + " " + spec.name);
            missingFunctions++;
            return;
        }

        foundFunctions++;
        String oldName = function.getName();
        try {
            if (!oldName.equals(spec.name)) {
                function.setName(spec.name, SourceType.USER_DEFINED);
            }
        }
        catch (Exception exc) {
            println("NAME_WARNING " + address + " " + spec.name + " " + exc.getMessage());
        }

        String comment = "[E64 recovered annotation]\n" + spec.comment
            + "\nELF address: 0x" + Long.toHexString(spec.elf)
            + "\nGhidra address: " + address;
        if (spec.parameters.length > 0) {
            comment += "\nRecovered formal variables: "
                + joinNames(spec.parameters);
        }
        String stateTypeName = stateTypeName(spec.name);
        if (stateTypeName != null) {
            comment += "\nRecovered object type: /E64Recovered/" + stateTypeName;
        }
        comment += "\nLocal temporaries remain storage-specific unless separately supported by instruction/data-flow evidence.";
        if (!oldName.equals(spec.name)) {
            comment += "\nPrevious imported name: " + oldName;
        }
        try {
            function.setComment(comment);
        }
        catch (Exception exc) {
            println("COMMENT_WARNING " + address + " " + exc.getMessage());
        }
        nameRecoveredParameters(function, spec.parameters);
    }

    private String joinNames(String[] names) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < names.length; i++) {
            if (i != 0) {
                result.append(", ");
            }
            result.append(names[i]);
        }
        return result.toString();
    }

    private String stateTypeName(String functionName) {
        if (functionName.contains("AlgorithmV1")) {
            return "AlgorithmV1State";
        }
        if (functionName.contains("AlgorithmV2")) {
            return "AlgorithmV2State";
        }
        if (functionName.contains("AlgorithmV3")) {
            return "AlgorithmV3State";
        }
        if (functionName.contains("AlgorithmV4")) {
            return "AlgorithmV4State";
        }
        if (functionName.contains("GbsService")) {
            return "GbsServiceState";
        }
        return null;
    }

    private boolean appliesToCurrentProgram(FunctionSpec spec) {
        String program = currentProgram.getName().toLowerCase();
        boolean hostEsp = program.contains("espwificonfig");
        boolean mainHmi = program.contains("libngxui");
        boolean hostOnly = spec.name.startsWith("e64_serial_")
            || spec.name.startsWith("e64_transport_pserial_");
        // The serial/protobuf utility is a separate ELF whose symbols are
        // direct addresses (offset 0). The main HMI library uses the recovered
        // +0x10000 presentation. Do not report utility symbols as missing from
        // the HMI program, and do not apply HMI callbacks to the utility.
        return hostOnly ? hostEsp : mainHmi;
    }

    private void nameRecoveredParameters(Function function, String[] names) {
        if (names.length == 0) {
            return;
        }
        Parameter[] parameters = function.getParameters();
        if (parameters.length == 0) {
            try {
                Variable[] recovered = new Variable[names.length];
                for (int i = 0; i < names.length; i++) {
                    ParameterImpl parameter = new ParameterImpl(
                        names[i], parameterDataType(function, names[i]),
                        currentProgram, SourceType.USER_DEFINED);
                    parameter.setComment("Recovered semantic parameter; ARM storage is dynamically assigned by Ghidra. "
                        + "Role is supported by the function signature/evidence notes.");
                    recovered[i] = parameter;
                }
                function.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                    true, SourceType.USER_DEFINED, recovered);
                parameters = function.getParameters();
                createdParameters += parameters.length;
                typedParameters += parameters.length;
                for (int i = 0; i < Math.min(parameters.length, names.length); i++) {
                    namedParameters++;
                }
                println("PARAM_CREATE " + function.getName() + " count="
                    + parameters.length);
                return;
            }
            catch (Exception exc) {
                println("PARAM_CREATE_WARNING " + function.getName() + " recovered="
                    + names.length + " " + exc.getMessage());
                // Keep the full names in the function plate comment below. A
                // failed signature update must never stop the full pass.
            }
        }
        int limit = Math.min(parameters.length, names.length);
        for (int i = 0; i < limit; i++) {
            try {
                parameters[i].setName(names[i], SourceType.USER_DEFINED);
                parameters[i].setDataType(parameterDataType(function, names[i]),
                    SourceType.USER_DEFINED);
                namedParameters++;
                typedParameters++;
            }
            catch (Exception exc) {
                println("PARAM_WARNING " + function.getName() + "[" + i + "] "
                    + names[i] + " " + exc.getMessage());
            }
        }
        if (parameters.length < names.length) {
            println("PARAM_HINT " + function.getName() + " existing="
                + parameters.length + " recovered=" + names.length);
        }
    }

    private DataType parameterDataType(Function function, String parameterName) {
        String name = parameterName.toLowerCase();
        if (name.equals("this")) {
            String functionName = function.getName();
            if (functionName.contains("AlgorithmV1") && algorithmV1StateType != null) {
                return new PointerDataType(algorithmV1StateType,
                    currentProgram.getDataTypeManager());
            }
            if (functionName.contains("AlgorithmV2") && algorithmV2StateType != null) {
                return new PointerDataType(algorithmV2StateType,
                    currentProgram.getDataTypeManager());
            }
            if (functionName.contains("AlgorithmV3") && algorithmV3StateType != null) {
                return new PointerDataType(algorithmV3StateType,
                    currentProgram.getDataTypeManager());
            }
            if (functionName.contains("AlgorithmV4") && algorithmV4StateType != null) {
                return new PointerDataType(algorithmV4StateType,
                    currentProgram.getDataTypeManager());
            }
            if (functionName.contains("GbsService") && gbsServiceStateType != null) {
                return new PointerDataType(gbsServiceStateType,
                    currentProgram.getDataTypeManager());
            }
            return PointerDataType.dataType;
        }
        if (name.equals("commanddef")) {
            return new PointerDataType(commandDefType,
                currentProgram.getDataTypeManager());
        }
        if (name.equals("history")) {
            return new PointerDataType(gbsSamplePointType,
                currentProgram.getDataTypeManager());
        }
        if (name.equals("brewinput") || name.equals("event")
            || name.equals("message") || name.equals("text")
            || name.equals("token") || name.equals("connection")
            || name.equals("recipe") || name.equals("algorithmkey")
            || name.equals("algorithmname") || name.equals("state")
            || name.equals("grind") || name.equals("gbsstate")
            || name.equals("json") || name.equals("output")
            || name.equals("outputddum") || name.equals("algorithm")
            || name.equals("frame")
            || name.equals("breweventstorage") || name.equals("recipeprovider")
            || name.equals("gbsstatestorage") || name.equals("patchableconfig")
            || name.equals("debugflags") || name.equals("parent")
            || name.equals("name") || name.equals("handle")
            || name.equals("bytesread") || name.equals("outbuffer")
            || name.equals("payload") || name.equals("buffer")) {
            return PointerDataType.dataType;
        }
        if (name.contains("factor") || name.contains("thresholdsec")
            || name.contains("temperaturec") || name.contains("valueum")
            || name.contains("distance") || name.contains("speedfield")
            || name.contains("frequencyhz") || name.contains("previousum")) {
            return DoubleDataType.dataType;
        }
        if (name.equals("enabled") || name.equals("validity")
            || name.equals("success") || name.equals("purge")) {
            return ByteDataType.dataType;
        }
        // Durations, DD values, enum values, IDs and booleans are represented
        // as 32-bit scalar values at the recovered C++ boundaries. This type
        // is intentionally a readable scalar, not a claim about every Qt
        // wrapper's source-level typedef.
        return DWordDataType.dataType;
    }

    private void createSafeLabel(Address address, String name) {
        try {
            currentProgram.getSymbolTable().createLabel(address, name,
                SourceType.USER_DEFINED);
            createdLabels++;
        }
        catch (Exception exc) {
            println("LABEL_WARNING " + address + " " + name + " " + exc.getMessage());
        }
    }

    private void installDataLabels() {
        // The protobuf descriptor addresses below are from EspWifiConfig.  A
        // prior broad guard also labeled coincidentally occupied HMI offsets,
        // which made the visual data view look as if the HMI owned the ESP
        // descriptor table.  Keep the labels tied to the proven program.
        if (!currentProgram.getName().toLowerCase().contains("espwificonfig")) {
            return;
        }
        labelElf(0x00353c8L, "e64_ctrl_msg_descriptor");
        labelElf(0x00342e8L, "e64_ctrl_msg_id_descriptor");
        labelElf(0x0034748L, "e64_ctrl_msg_type_descriptor");
        labelElf(0x00347e8L, "e64_ctrl_status_descriptor");
        if (currentProgram.getName().toLowerCase().contains("espwificonfig")) {
            labelElf(0x00374a4L, "e64_ctrl_request_semaphore");
            labelElf(0x00374a8L, "e64_ctrl_library_context");
            labelElf(0x00374acL, "e64_ctrl_event_callback_table");
            labelElf(0x00374c4L, "e64_ctrl_response_callback_table");
            labelElf(0x003751cL, "e64_ctrl_rx_thread_handle");
            labelElf(0x0037520L, "e64_ctrl_message_queue");
            labelElf(0x0037524L, "e64_serial_driver_handle");
        }
    }

    private void labelElf(long elfAddress, String name) {
        try {
            createSafeLabel(resolveElf(elfAddress), name);
        }
        catch (Exception exc) {
            println("DATA_LABEL_MISSING 0x" + Long.toHexString(elfAddress)
                + " " + name);
        }
    }

    private void installRecoveredDataTypes() {
        DataTypeManager manager = currentProgram.getDataTypeManager();
        CategoryPath category = new CategoryPath("/E64Recovered");

        StructureDataType sample = new StructureDataType(category,
            "GbsSamplePoint", 0x10, manager);
        addField(sample, DoubleDataType.dataType, 0x00, 8, "setpointUm",
            "Recovered first regression coordinate; deci-um input converted to um.");
        addField(sample, DoubleDataType.dataType, 0x08, 8, "actualSec",
            "Recovered observed brew duration in seconds.");
        gbsSamplePointType = manager.addDataType(sample,
            DataTypeConflictHandler.KEEP_HANDLER);

        StructureDataType command = new StructureDataType(category,
            "CommandDef", 0x1c, manager);
        addField(command, PointerDataType.dataType, 0x00, 4, "type",
            "top-level command type");
        addField(command, PointerDataType.dataType, 0x04, 4, "actionType",
            "action suffix or null");
        addField(command, ByteDataType.dataType, 0x08, 1, "logEnabled",
            "registry flag");
        addField(command, ByteDataType.dataType, 0x09, 1, "developmentOnly",
            "registry flag");
        addField(command, ByteDataType.dataType, 0x0a, 1, "tokenRequired",
            "registry flag");
        addField(command, ByteDataType.dataType, 0x0b, 1, "unresolvedPadding",
            "layout byte");
        addField(command, PointerDataType.dataType, 0x0c, 4, "callback",
            "callback pointer");
        addField(command, new ArrayDataType(ByteDataType.dataType, 12, 1),
            0x10, 12, "unresolvedTail", "record tail not decoded");
        commandDefType = manager.addDataType(command,
            DataTypeConflictHandler.KEEP_HANDLER);

        StructureDataType brew = new StructureDataType(category,
            "RecoveredBrewInput", 0, manager);
        addField(brew, DWordDataType.dataType, 0x00, 4,
            "actualBrewDurationMs", "input");
        addField(brew, DWordDataType.dataType, 0x04, 4,
            "targetBrewDurationMs", "input");
        addField(brew, DWordDataType.dataType, 0x08, 4, "estimatedDdDum",
            "deci-um input");
        addField(brew, DWordDataType.dataType, 0x0c, 4, "setpointDdDum",
            "deci-um input");
        addField(brew, DWordDataType.dataType, 0x10, 4, "toleranceMs",
            "input");
        recoveredBrewInputType = manager.addDataType(brew,
            DataTypeConflictHandler.KEEP_HANDLER);

        StructureDataType uart = new StructureDataType(category,
            "RecoveredUartEnvelope", 0, manager);
        addField(uart, ByteDataType.dataType, 0x00, 1, "dataType",
            "must be 1");
        addField(uart, WordDataType.dataType, 0x01, 2, "endpointLength",
            "little-endian length is 8");
        addField(uart, new ArrayDataType(ByteDataType.dataType, 8, 1),
            0x03, 8, "endpoint", "ctrlResp or ctrlEvnt");
        addField(uart, ByteDataType.dataType, 0x0b, 1, "messageType",
            "must be 2");
        addField(uart, WordDataType.dataType, 0x0c, 2, "protobufLength",
            "little-endian payload length");
        recoveredUartEnvelopeType = manager.addDataType(uart,
            DataTypeConflictHandler.KEEP_HANDLER);

        EnumDataType ctrlType = new EnumDataType(category, "CtrlMsgType", 4, manager);
        ctrlType.add("INVALID", 0);
        ctrlType.add("REQUEST", 1);
        ctrlType.add("RESPONSE", 2);
        ctrlType.add("EVENT", 3);
        manager.addDataType(ctrlType, DataTypeConflictHandler.KEEP_HANDLER);

        algorithmV1StateType = installAlgorithmV1State(category, manager);
        algorithmV2StateType = installAlgorithmV2State(category, manager);
        algorithmV3StateType = installAlgorithmV3State(category, manager);
        algorithmV4StateType = installAlgorithmV4State(category, manager);
        gbsServiceStateType = installGbsServiceState(category, manager);
        println("RECOVERED_TYPES CommandDef, RecoveredBrewInput, RecoveredUartEnvelope, "
            + "GbsSamplePoint, AlgorithmV1State, AlgorithmV2State, AlgorithmV3State, "
            + "AlgorithmV4State, GbsServiceState, CtrlMsgType");
    }

    private void addField(StructureDataType structure, DataType type, int offset,
                          int length, String name, String comment) {
        try {
            structure.insertAtOffset(offset, type, length, name, comment);
        }
        catch (Exception exc) {
            println("TYPE_FIELD_WARNING " + structure.getName() + "." + name
                + " " + exc.getMessage());
        }
    }

    private DataType installAlgorithmV1State(CategoryPath category,
                                             DataTypeManager manager) {
        StructureDataType state = new StructureDataType(category,
            "AlgorithmV1State", 0x40, manager);
        addField(state, PointerDataType.dataType, 0x00, 4, "vtable",
            "compiler-generated polymorphic object prefix");
        addField(state, ByteDataType.dataType, 0x04, 1, "debugEnabled",
            "debug flag");
        addField(state, DWordDataType.dataType, 0x08, 4, "historyCapacity",
            "default 4");
        addField(state, DWordDataType.dataType, 0x0c, 4, "centralWidth",
            "default 2");
        addField(state, new ArrayDataType(ByteDataType.dataType, 12, 1),
            0x10, 12, "historyVector", "vector pointers; element layout is separate");
        addField(state, DoubleDataType.dataType, 0x20, 8, "continuousUm",
            "continuous coarseness state");
        addField(state, DoubleDataType.dataType, 0x28, 8, "quantizedUm",
            "previous quantized coarseness");
        addField(state, DoubleDataType.dataType, 0x30, 8, "lastMedianActualSec",
            "last median actual duration");
        addField(state, DWordDataType.dataType, 0x38, 4, "lastResultDum",
            "optional result, deci-um");
        addField(state, ByteDataType.dataType, 0x3c, 1, "lastResultEngaged",
            "optional engagement byte");
        return manager.addDataType(state, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private DataType installAlgorithmV2State(CategoryPath category,
                                             DataTypeManager manager) {
        StructureDataType state = new StructureDataType(category,
            "AlgorithmV2State", 0x38, manager);
        addField(state, PointerDataType.dataType, 0x00, 4, "vtable",
            "compiler-generated polymorphic object prefix");
        addField(state, new ArrayDataType(ByteDataType.dataType, 40, 1),
            0x08, 40, "sampleDeque", "one deque, maximum six GbsSamplePoint entries");
        addField(state, DWordDataType.dataType, 0x30, 4, "lastResultDum",
            "optional result, deci-um");
        addField(state, ByteDataType.dataType, 0x34, 1, "lastResultEngaged",
            "optional engagement byte");
        return manager.addDataType(state, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private DataType installAlgorithmV3State(CategoryPath category,
                                             DataTypeManager manager) {
        StructureDataType state = new StructureDataType(category,
            "AlgorithmV3State", 0xd0, manager);
        addField(state, PointerDataType.dataType, 0x00, 4, "vtable",
            "compiler-generated polymorphic object prefix");
        addField(state, ByteDataType.dataType, 0x4c, 1, "debugEnabled",
            "debug flag");
        addField(state, new ArrayDataType(ByteDataType.dataType, 40, 1),
            0x50, 40, "sampleDeque", "one deque, maximum six GbsSamplePoint entries");
        addField(state, DoubleDataType.dataType, 0x78, 8, "farFactor",
            "default 0.0");
        addField(state, DoubleDataType.dataType, 0x80, 8, "midFactor",
            "default 0.5");
        addField(state, DoubleDataType.dataType, 0x88, 8, "nearFactor",
            "default 1.0");
        addField(state, DoubleDataType.dataType, 0x90, 8, "filterRetention",
            "default 0.5");
        addField(state, DWordDataType.dataType, 0x98, 4, "holdCyclesSetting",
            "default 2");
        addField(state, DWordDataType.dataType, 0x9c, 4, "holdCyclesRemaining",
            "countdown");
        addField(state, DWordDataType.dataType, 0xa0, 4, "lastTargetDum",
            "optional target, deci-um");
        addField(state, ByteDataType.dataType, 0xa4, 1, "lastTargetEngaged",
            "optional engagement byte");
        addField(state, DWordDataType.dataType, 0xa8, 4, "lastAdjustmentDum",
            "optional adjustment, deci-um");
        addField(state, ByteDataType.dataType, 0xac, 1, "lastAdjustmentEngaged",
            "optional engagement byte");
        addField(state, DoubleDataType.dataType, 0xb0, 8,
            "filteredDdTimesBrew", "filtered DD-times-brew value");
        addField(state, DoubleDataType.dataType, 0xc0, 8,
            "nearThresholdSec", "default 2.0 seconds");
        addField(state, ByteDataType.dataType, 0xc8, 1,
            "keepMediumIntervalWidth", "Algorithm-3 policy flag");
        return manager.addDataType(state, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private DataType installAlgorithmV4State(CategoryPath category,
                                             DataTypeManager manager) {
        StructureDataType state = new StructureDataType(category,
            "AlgorithmV4State", 0x80, manager);
        addField(state, PointerDataType.dataType, 0x00, 4, "vtable",
            "compiler-generated polymorphic object prefix");
        addField(state, ByteDataType.dataType, 0x08, 1, "debugEnabled",
            "debug flag");
        addField(state, new ArrayDataType(ByteDataType.dataType, 40, 1),
            0x0c, 40, "sampleDeque", "one deque, maximum six GbsSamplePoint entries");
        addField(state, DoubleDataType.dataType, 0x38, 8, "farFactor",
            "default 0.0");
        addField(state, DoubleDataType.dataType, 0x40, 8, "midFactor",
            "default 0.5");
        addField(state, DoubleDataType.dataType, 0x48, 8, "nearFactor",
            "default 1.0");
        addField(state, DoubleDataType.dataType, 0x50, 8, "filterRetention",
            "default 0.5");
        addField(state, DWordDataType.dataType, 0x58, 4, "holdCyclesSetting",
            "default 2");
        addField(state, DWordDataType.dataType, 0x5c, 4, "holdCyclesRemaining",
            "countdown");
        addField(state, DWordDataType.dataType, 0x60, 4, "lastTargetDum",
            "optional target, deci-um");
        addField(state, ByteDataType.dataType, 0x64, 1, "lastTargetEngaged",
            "optional engagement byte");
        addField(state, DWordDataType.dataType, 0x68, 4, "lastAdjustmentDum",
            "optional adjustment, deci-um");
        addField(state, ByteDataType.dataType, 0x6c, 1, "lastAdjustmentEngaged",
            "optional engagement byte");
        addField(state, DoubleDataType.dataType, 0x70, 8,
            "filteredDdTimesBrew", "filtered DD-times-brew value");
        return manager.addDataType(state, DataTypeConflictHandler.KEEP_HANDLER);
    }

    private DataType installGbsServiceState(CategoryPath category,
                                            DataTypeManager manager) {
        StructureDataType slot = new StructureDataType(category,
            "GbsRecipeSlot", 0x30, manager);
        addField(slot, ByteDataType.dataType, 0x28, 1, "engaged",
            "normal recipe-slot engagement byte");
        DataType slotType = manager.addDataType(slot,
            DataTypeConflictHandler.KEEP_HANDLER);

        StructureDataType service = new StructureDataType(category,
            "GbsServiceState", 0x2a0, manager);
        addField(service, PointerDataType.dataType, 0x18, 4,
            "brewEventStorage", "service dependency");
        addField(service, PointerDataType.dataType, 0x1c, 4,
            "recipeProvider", "service dependency");
        addField(service, PointerDataType.dataType, 0x20, 4,
            "gbsStateStorage", "service dependency");
        addField(service, PointerDataType.dataType, 0x24, 4,
            "patchableConfig", "service dependency");
        addField(service, new ArrayDataType(ByteDataType.dataType, 24, 1),
            0x28, 24, "effectiveDdPrediction", "24-byte recovered object");
        addField(service, PointerDataType.dataType, 0x40, 4,
            "algorithmCache", "unordered-map/cache anchor");
        addField(service, new ArrayDataType(slotType, 6, 0x30),
            0x60, 0x120, "recipeSlots", "six normal slots; each engagement at +0x28");
        addField(service, ByteDataType.dataType, 0x208, 1,
            "specialStateEngaged", "special recipe-state engagement byte");
        addField(service, PointerDataType.dataType, 0x210, 4,
            "pendingTimer", "five-minute pending-brew timer");
        addField(service, DWordDataType.dataType, 0x21c, 4,
            "pendingTimerIntervalMs", "recovered value 300000");
        addField(service, new ArrayDataType(ByteDataType.dataType, 0x60, 1),
            0x230, 0x60, "pendingBrew", "pending object; selected fields documented separately");
        addField(service, DWordDataType.dataType, 0x290, 4,
            "preventAgsaBrewtimeRangeMs", "runtime policy value");
        return manager.addDataType(service, DataTypeConflictHandler.KEEP_HANDLER);
    }
}
