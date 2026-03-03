name: ai-threat-analyzer
description: Sistema de predicción y prevención de amenazas de seguridad impulsado por IA
version: 1.0.0
author: OpenClaw Security Team
tags: ["threat-modeling", "security", "ai", "predictive", "prevention"]
requires: ["python3.9+", "docker", "git", "openclaw-cli"]
dependencies:
  - name: transformers
    version: ">=4.30.0"
  - name: torch
    version: ">=2.0.0"
  - name: bandit
    version: ">=1.7.5"
  - name: semgrep
    version: ">=1.50.0"
  - name: trivy
    version: ">=0.45.0"
  - name: grype
    version: ">=0.75.0"
env_vars:
  - name: OPENCLAW_AI_MODEL
    default: "microsoft/codebert-base"
    description: "Modelo de IA para análisis de código"
  - name: THREAT_SCAN_CONFIDENCE
    default: "0.7"
    description: "Umbral mínimo de confianza (0-1)"
  - name: OPENCLAW_AI_API_KEY
    description: "Clave API para inferencia remota de modelo IA (opcional)"
---

# Habilidad de Analizador de Amenazas IA

## Propósito

AI Threat Analyzer predice y previene vulnerabilidades de seguridad analizando código, dependencias, infraestructura como código y archivos de configuración mediante un enfoque híbrido que combina análisis estático, modelos de machine learning e inteligencia de amenazas.

**Casos de Uso Reales:**
- Detectar vulnerabilidades sutiles de inyección en servicios Node.js/Python que las herramientas tradicionales pasan por alto
- Predecir problemas de seguridad futuros basándose en complejidad de código y patrones de desarrollo
- Identificar riesgos de cadena de suministro en dependencias npm/PyPI antes de que sean explotadas
- Analizar manifiestos Terraform/Kubernetes en busca de configuraciones erróneas que puedan exponer datos
- Generar recomendaciones de codificación segura adaptadas a tu stack (React, Django, FastAPI, etc.)
- Priorizar vulnerabilidades según probabilidad de explotación evaluada por IA e impacto empresarial

## Alcance

Esta habilidad proporciona los siguientes comandos:

### `openclaw skill ai-threat-analyzer scan-code [options] <path>`

Realiza análisis estático mejorado con IA en el código fuente.

**Flags:**
- `--language=<lang>` - Lenguaje objetivo: `python`, `javascript`, `go`, `java`, `all` (por defecto: auto-detección)
- `--severity=<level>` - Severidad mínima: `low`, `medium`, `high`, `critical` (por defecto: `medium`)
- `--model=<path|huggingface>` - Ruta de modelo personalizada o ID de HuggingFace (por defecto: env OPENCLAW_AI_MODEL)
- `--confidence=<0.0-1.0>` - Umbral de confianza de IA (por defecto: 0.7)
- `--context-lines=<n>` - Incluir N líneas de contexto en informes (por defecto: 5)
- `--exclude=<pattern>` - Excluir rutas que coincidan con patrón glob (repetible)
- `--output=<format>` - Formato de salida: `json`, `sarif`, `html`, `terminal` (por defecto: terminal)
- `--include-suppressed` - Incluir predicciones suprimidas/falsos positivos

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer scan-code ./services/api --language python --severity medium --output sarif --context-lines 3
```

### `openclaw skill ai-threat-analyzer scan-deps [options] <manifest>`

Analiza dependencias en busca de CVEs conocidos, riesgos de cadena de suministro y patrones sospechosos.

**Flags:**
- `--type=<type>` - Tipo de manifiesto: `npm`, `pip`, `cargo`, `gomod`, `all` (por defecto: auto)
- `--depth=<n>` - Profundidad del árbol de dependencias a analizar (por defecto: 3, máximo: 10)
- `--include-dev` - Incluir devDependencies (por defecto: false)
- `--check-license` - Marcar licencias restrictivas (por defecto: true)
- `--taint-tracking` - Rastrear flujo de datos desde dependencias vulnerables hasta el código (por defecto: true)
- `--output=<format>` - `json`, `table`, `github-annotations`
- `--fix-pr` - Crear PR con actualizaciones automatizadas para dependencias vulnerables

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer scan-deps ./package.json --taint-tracking --output github-annotations
```

### `openclaw skill ai-threat-analyzer scan-infra [options] <path>`

Escanea infraestructura como código en busca de configuraciones de seguridad erróneas.

**Flags:**
- `--iac-types=<list>` - Separado por comas: `terraform,kubernetes,cloudformation,docker,helm` (por defecto: todas)
- `--policy=<path>` - Bundle de políticas OPA/Open Policy Agent personalizado
- `--cloud-provider=<provider>` - Contexto para verificaciones específicas de nube: `aws`, `gcp`, `azure`, `all`
- `--simulate-attacks` - Generar escenarios de ataque basados en configuraciones erróneas (por defecto: false)
- `--output=<format>` - `json`, `sarif`, `cli-table`

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer scan-infra ./infra --iac-types terraform,kubernetes --cloud-provider aws --simulate-attacks
```

### `openclaw skill ai-threat-analyzer predict-threat [options] <code-or-config>`

El modelo de IA predice cómo un cambio de código o configuración podría ser explotado en los próximos 90 días.

**Flags:**
- `--timeframe=<days>` - Ventana de predicción: 30, 60, 90 días (por defecto: 90)
- `--asset-type=<type>` - Clasificación de activo: `public-facing`, `internal`, `pci`, `hipaa`, `generic`
- `--patch-rush` - Predicción acelerada para parches de emergencia (menor precisión, más rápido)

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer predict-threat ./src/auth.py --asset-type public-facing
```

### `openclaw skill ai-threat-analyzer apply-fixes [options] <scan-result>`

Aplica automáticamente correcciones recomendadas por IA donde la confianza sea >90%.

**Flags:**
- `--dry-run` - Mostrar correcciones sin aplicar (por defecto: false)
- `--max-fixes=<n>` - Correcciones máximas a aplicar en una ejecución (por defecto: 10)
- `--require-approval` - Aprobación interactiva por cada corrección (por defecto: true)
- `--backup-dir=<path>` - Crear copias de seguridad antes de modificaciones
- `--git-commit` - Crear commit de git para cada corrección aplicada
- `--pr` - Crear pull request con todas las correcciones en lugar de aplicar directamente

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer apply-fixes ./scan-results.json --pr --require-approval --backup-dir ./backups
```

### `openclaw skill ai-threat-analyzer train-model [options] <dataset>`

Ajusta finamente el modelo IA con datos históricos de vulnerabilidades de tu organización.

**Flags:**
- `--base-model=<hf-id>` - Modelo base de HuggingFace (por defecto: microsoft/codebert-base)
- `--epochs=<n>` - Épocas de entrenamiento (por defecto: 5)
- `--batch-size=<n>` - Tamaño de lote de entrenamiento (por defecto: 16)
- `--validation-split=<float>` - Ratio de división de validación (por defecto: 0.2)
- `--output-dir=<path>` - Dónde guardar el modelo ajustado (por defecto: ./models/threat-analyzer)
- `--push-to-hub` - Subir a HuggingFace Hub (requiere AUTH_TOKEN)

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer train-model ./historical-vulns.jsonl --epochs 10 --output-dir ./models/custom-threat-analyzer --batch-size 32
```

### `openclaw skill ai-threat-analyzer explain-finding <finding-id>`

Proporciona explicación detallada y contextual de una vulnerabilidad específica con pasos de remediación.

**Flags:**
- `--format=<format>` - `text`, `markdown`, `json` (por defecto: markdown)
- `--audience=<level>` - Personalizar explicación: `developer`, `security-engineer`, `manager` (por defecto: developer)
- `--include-code-samples` - Proporcionar ejemplos de código seguro vs vulnerable (por defecto: true)

**Ejemplo:**
```bash
openclaw skill ai-threat-analyzer explain-finding SQLI-2024-12345 --audience developer --format markdown
```

## Proceso de Trabajo Detallado

### Flujo de trabajo estándar de análisis de vulnerabilidades:

1. **Preparación**
   ```bash
   # Establecer umbral de confianza para tu apetito de riesgo
   export THREAT_SCAN_CONFIDENCE=0.75
   
   # Apuntar a modelo personalizado si está disponible
   export OPENCLAW_AI_MODEL="./models/fine-tuned-threat-analyzer"
   ```

2. **Ejecutar escaneo multi-capa**
   ```bash
   # Escaneo paralelo de código, dependencias e infraestructura
   openclaw skill ai-threat-analyzer scan-code ./src --output json > code-scan.json &
   openclaw skill ai-threat-analyzer scan-deps ./package.json --output json > deps-scan.json &
   openclaw skill ai-threat-analyzer scan-infra ./infra --output json > infra-scan.json &
   
   wait
   
   # Combinar resultados
   cat code-scan.json deps-scan.json infra-scan.json | jq -s 'add' > combined-threats.json
   ```

3. **Revisar predicciones**
   ```bash
   # Obtener top 10 hallazgos críticos con explicaciones de IA
   openclaw skill ai-threat-analyzer explain-finding --audience security-engineer --format json $(jq -r '.[] | select(.severity=="critical") | .id' combined-threats.json | head -10) > critical-explanations.json
   
   # Generar plan de acción priorizado
   openclaw skill ai-threat-analyzer predict-threat ./src --asset-type public-facing > threat-predictions.json
   ```

4. **Aplicar correcciones con validación**
   ```bash
   # Crear PR con correcciones (requiere revisión)
   openclaw skill ai-threat-analyzer apply-fixes combined-threats.json --pr --require-approval --max-fixes 20 --backup-dir ./threat-fix-backups
   
   # Después de aprobación y merge del PR, verificar correcciones
   # (re-ejecutar el escaneo para confirmar que los problemas se resolvieron)
   ```

5. **Mejora continua**
   ```bash
   # Ajustar finamente en falsos positivos/negativos para mejorar precisión
   # Exportar hallazgos revisados a dataset de entrenamiento
   jq '[.[] | select(.reviewed==true)]' threat-reviews.jsonl > training-data.jsonl
   
   # Reentrenar modelo mensualmente
   openclaw skill ai-threat-analyzer train-model ./training-data.jsonl --epochs 3 --output-dir ./models/monthly-$(date +%Y%m)
   ```

### Ejemplo de Integración CI/CD:

```yaml
# .github/workflows/threat-scan.yml
name: AI Threat Scan
on:
  pull_request:
    paths:
      - '**.py'
      - '**.js'
      - '**.tf'
      - 'package.json'
      - 'requirements.txt'

jobs:
  threat-analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install OpenClaw
        run: curl -sSL https://openclaw.io/install.sh | bash
      - name: AI Threat Scan
        run: |
          openclaw skill ai-threat-analyzer scan-code . --output sarif > threats.sarif
          openclaw skill ai-threat-analyzer scan-deps . --output sarif >> threats.sarif
          openclaw skill ai-threat-analyzer scan-infra ./infra --output sarif >> threats.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: threats.sarif
      - name: Fail on Critical
        run: |
          if jq -e '.[] | select(.severity=="critical" and (.confidence // 1) > 0.8)' threats.sarif > /dev/null; then
            echo "Critical threats detected!"
            exit 1
          fi
```

## Reglas de Oro

1. **Umbrales de Confianza**
   - Solo aplicar automáticamente correcciones con >90% de confianza de IA
   - Revisión manual requerida para hallazgos de severidad Medium+ con 70-90% de confianza
   - Hallazgos de baja confianza (<70%) deben ser validados manualmente antes de cualquier acción

2. **Privacidad de Datos**
   - Nunca enviar código propietario a APIs de IA externas sin permiso explícito
   - Preferir inferencia de modelo local con `--model="./local-model"`
   - Si se usan APIs remotas, asegurar que los datos estén anonimizados y la transmisión sea cifrada TLS
   - Configurar `OPENCLAW_AI_API_KEY` con tokens de alcance limitado únicamente

3. **Gestión de Cambios**
   - Nunca usar `--dry-run false` (es decir, cambios reales) sin copias de seguridad
   - Siempre ejecutar `--backup-dir` al aplicar correcciones
   - Limitar auto-correcciones a 20 por ejecución para evitar cambios masivos no deseados
   - Requerir aprobación humana para cualquier corrección que toque código de autenticación, autorización o cifrado

4. **Gestión de Modelos**
   - Versionar modelos ajustados con versionado semántico
   - Mantener modelo base inmutable; crear nuevas versiones ajustadas en lugar de sobrescribir
   - Probar modelos ajustados en conjunto de validación antes de despliegue en producción
   - Archivar todos los datasets de entrenamiento con resultados de escaneo para reproducibilidad

5. **Manejo de Falsos Positivos**
   - Marcar falsos positivos con flag `--include-suppressed` para reentrenar modelo
   - NO suprimir hallazgos sin agregarlos al bucle de retroalimentación de entrenamiento
   - Rastrear tasa de falsos positivos por modelo; reentrenar si tasa excede 15%

6. **Seguridad de Cadena de Suministro**
   - Siempre incluir `--taint-tracking` para escaneos de dependencias
   - Nunca usar `--include-dev` en builds de producción sin aprobación de seguridad explícita
   - Bloquear cualquier dependencia marcada como `malicious` o `typosquatting` automáticamente

## Ejemplos

### Ejemplo 1: Detectando una inyección SQL sutil en Django

**Comando:**
```bash
openclaw skill ai-threat-analyzer scan-code ./django-app --language python --severity medium --output json
```

**Código de entrada (django-app/views.py):**
```python
def search_users(request):
    query = request.GET.get('q', '')
    # Vulnerable: SQL raw con formateo de cadena
    User.objects.raw(f"SELECT * FROM users WHERE name = '{query}'")
```

**Salida:**
```json
{
  "scan_id": "scan-2024-03-15-threat-001",
  "findings": [
    {
      "id": "SQLI-2024-12345",
      "severity": "high",
      "confidence": 0.92,
      "type": "SQL Injection",
      "file": "django-app/views.py",
      "line": 5,
      "code_snippet": "User.objects.raw(f\"SELECT * FROM users WHERE name = '{query}'\")",
      "ai_explanation": "El parámetro de consulta 'query' se interpola directamente en SQL sin parametrización. Los atacantes pueden inyectar SQL vía parámetro URL 'q'. A diferencia de herramientas básicas que detectan SQL raw, nuestra IA reconoce el método raw() del ORM de Django como de alto riesgo cuando se combina con f-strings. Explotación probable dentro de 30 días para apps públicas.",
      "cwe": "CWE-89",
      "owasp": "A03:2021 – Injection",
      "fix_suggestion": "Usar consultas parametrizadas: User.objects.raw('SELECT * FROM users WHERE name = %s', [query])",
      "exploitability_score": 8.5,
      "impact_score": 9.0,
      "priority": "P1"
    }
  ]
}
```

**Verificación:**
```bash
# Confirmar que el hallazgo existe con la severidad esperada
jq '.findings[] | select(.id=="SQLI-2024-12345")' scan-results.json
# Debería retornar hallazgo con confianza >= 0.9
```

**Rollback:**
```bash
# Si la corrección aplicada causa problemas:
git checkout HEAD -- django-app/views.py
# O restaurar desde backup si se usó backup-dir:
cp ./backups/views.py.bak ./django-app/views.py
```

### Ejemplo 2: Detección de riesgo de cadena de suministro en dependencias

**Comando:**
```bash
openclaw skill ai-threat-analyzer scan-deps ./package.json --taint-tracking --output json
```

**Entrada (package.json):**
```json
{
  "dependencies": {
    "lodash": "4.17.15",
    "pyodide": "0.23.4"
  }
}
```

**Salida:**
```json
{
  "findings": [
    {
      "id": "DEP-2024-67890",
      "severity": "critical",
      "confidence": 0.88,
      "type": "Prototype Pollution",
      "dependency": "lodash@4.17.15",
      "cve": "CVE-2019-10744",
      "ai_analysis": "Las versiones de lodash <4.17.21 contienen pollution de prototipo en merge() y set(). Tu versión (4.17.15) es vulnerable. La IA marcó esto porque tu codebase usa _.merge() en src/utils/js/deepMerge.js (linea 12), creando un camino explotable.",
      "taint_path": [
        "package.json:lodash@4.17.15",
        "src/utils/js/deepMerge.js:12:_.merge(config, defaults)",
        "Entrada controlada por usuario fluye a merge() desde cuerpo de petición HTTP"
      ],
      "fix": "Actualizar a lodash@4.17.21 o reemplazar con Object.assign() nativo",
      "affected_services": ["frontend", "admin-panel"],
      "priority": "P0"
    },
    {
      "id": "DEP-2024-67891",
      "severity": "medium",
      "confidence": 0.76,
      "type": "Suspicious Package",
      "dependency": "pyodide@0.23.4",
      "ai_analysis": "Pyodide descarga y ejecuta paquetes Python en runtime. El modelo de IA identifica esto como inusual para un frontend web, potencialmente introduciendo paquetes Python no examinados que podrían ejecutar código malicioso.",
      "recommendation": "Auditar todas las llamadas pyodide.loadPackage(); considerar empaquetar los paquetes Python requeridos",
      "priority": "P2"
    }
  ]
}
```

**Aplicación de corrección:**
```bash
# Crear PR con actualizaciones automatizadas de dependencias y cambios de código requeridos
openclaw skill ai-threat-analyzer apply-fixes ./dep-scan.json --pr --require-approval --git-commit
```

**Verificación:**
```bash
# Después del merge del PR, verificar dependencias vulnerables removidas
npm list lodash | grep -q "4.17.21" || echo "¡lodash no actualizado!"
```

**Rollback:**
```bash
# Si lodash actualizado rompe compatibilidad, revertir a versión anterior
npm install lodash@4.17.15
# Revertir cambios del PR:
git revert <merge-commit>
```

### Ejemplo 3: Configuración errónea de infraestructura en Terraform

**Comando:**
```bash
openclaw skill ai-threat-analyzer scan-infra ./terraform --iac-types terraform --cloud-provider aws --output json
```

**Entrada (terraform/main.tf):**
```hcl
resource "aws_s3_bucket" "public_data" {
  bucket_prefix = "public-data-"
  acl           = "public-read"
}

resource "aws_security_group" "web_sg" {
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
```

**Salida:**
```json
{
  "findings": [
    {
      "id": "INFRA-2024-11111",
      "severity": "high",
      "confidence": 0.95,
      "type": "Overly Permissive S3 ACL",
      "resource": "aws_s3_bucket.public_data",
      "ai_explanation": "El bucket S3 'public-data-*' tiene ACL 'public-read'. El modelo de IA reconoce esto como riesgo de exposición de datos, especialmente para buckets que contienen datos de usuarios. Combinado con la previsibilidad de bucket_prefix, esto es vulnerable a acceso no autorizado de datos.",
      "attack_scenario": "El atacante adivina el nombre del bucket vía patrón de nomenclatura común, lee todos los objetos públicamente, extrae PII.",
      "fix": "Remover 'acl' y usar aws_s3_bucket_policy con grants explícitos. Habilitar cifrado del lado del servidor por defecto.",
      "priority": "P1"
    },
    {
      "id": "INFRA-2024-11112",
      "severity": "critical",
      "confidence": 0.98,
      "type": "Unrestricted Security Group",
      "resource": "aws_security_group.web_sg",
      "ai_explanation": "El grupo de seguridad permite TODOS los puertos (0-65535) de CUALQUIER fuente (0.0.0.0/0). Esto expone toda la pila de aplicaciones a escaneo de internet y explotación. La IA marca esto como riesgo de brecha inmediata.",
      "attack_scenario": "Escaneo de puertos revela puerto de base de datos abierto (5432), el atacante se conecta directamente a PostgreSQL sin filtrado de autenticación.",
      "fix": "Restringir ingress a puertos específicos (80, 443) desde CIDR conocidos. Usar grupos de seguridad separados para app, DB y servicios internos.",
      "priority": "P0"
    }
  ]
}
```

**Verificación:**
```bash
# Verificar que terraform plan no cree buckets S3 vulnerables
terraform plan | grep -q "public-read" && echo "¡Configuración vulnerable aún presente!" || echo "Configuración S3 segura"
```

**Rollback:**
```bash
# Si la corrección introduce cambios disruptivos, revertir estado terraform
terraform apply -var="revert_acl=vulnerable"  # O revertir manualmente archivos .tf y re-aplicar
```

### Ejemplo 4: Prediciendo amenazas futuras desde complejidad de código

**Comando:**
```bash
openclaw skill ai-threat-analyzer predict-threat ./src/auth --asset-type public-facing --timeframe 90
```

**Salida:**
```json
{
  "prediction_id": "pred-2024-03-15-0001",
  "asset": "./src/auth (public-facing)",
  "target_date": "2024-06-13",
  "threats": [
    {
      "type": "Authentication Bypass",
      "likelihood": 0.73,
      "reasoning": "El modelo de IA detectó alta complejidad ciclomática (28) en función authenticate() con múltiples returns tempranos. Patrones históricos muestran que los saltos de autenticación emergen 60-90 días después que la complejidad excede 25.",
      "recommended_action": "Refactorizar authenticate() en funciones más pequeñas con máquina de estados explícita. Añadir property-based testing con Hypothesis.",
      "potential_impact": "Compromiso completo del sistema"
    },
    {
      "type": "JWT Algorithm Confusion",
      "likelihood": 0.41,
      "reasoning": "El código usa pyjwt sin verificación de algoritmo explícita (linea 89: jwt.decode(token)). Combinado con uso RSA/ECDSA en otros lugares, posible ataque de confusión de algoritmo.",
      "recommended_action": "Forzar algoritmo: jwt.decode(token, key=public_key, algorithms=['RS256'])",
      "potential_impact": "Escalada de privilegios a cualquier usuario"
    }
  ]
}
```

**Verificación:**
```bash
# Verificar línea base de complejidad antes de refactorizar
radon cc ./src/auth/authenticate.py -a | grep -q "Complexity: 28"
```

**Rollback:**
```bash
# Si el refactor rompe flujo de autenticación, revertir desde git
git log --oneline -- src/auth/authenticate.py | head -5
git revert <commit-before-refactor>
```

### Ejemplo 5: Entrenando un modelo personalizado con datos de vulnerabilidades de la organización

**Dataset (historical-vulns.jsonl):**
```json
{"code":"cursor.execute(\"SELECT * FROM users WHERE id=\"+user_id)","language":"python","vulnerable":true,"cwe":"CWE-89"}
{"code":"query = \"SELECT * FROM posts WHERE author='\"+author+\"'\"","language":"python","vulnerable":true,"cwe":"CWE-89"}
{"code":"cursor.execute(\"INSERT INTO logs(message)VALUES(?)\",(message,))","language":"python","vulnerable":false,"cwe":null}
```

**Comando:**
```bash
openclaw skill ai-threat-analyzer train-model ./historical-vulns.jsonl --epochs 10 --output-dir ./models/company-threat-analyzer --batch-size 32 --validation-split 0.2
```

**Salida:**
```text
[Salida de Entrenamiento]
Epoch 1/10: loss=0.342, accuracy=0.765
Epoch 2/10: loss=0.218, accuracy=0.842
...
Epoch 10/10: loss=0.045, accuracy=0.987

Resultados de Validación:
- Precision: 0.94
- Recall: 0.91
- F1-Score: 0.925

Modelo guardado en: ./models/company-threat-analyzer
✓ Modelo ajustado supera baseline por +4.2% F1 en datos de la organización
```

**Verificación:**
```bash
# Probar modelo ajustado en conjunto de validación
openclaw skill ai-threat-analyzer scan-code ./test-suite --model ./models/company-threat-analyzer --output json | jq '.findings | length'
# Debería detectar >90% de vulnerabilidades plantadas
```

**Rollback:**
```bash
# Revertir a modelo baseline
export OPENCLAW_AI_MODEL="microsoft/codebert-base"
# O eliminar modelo personalizado
rm -rf ./models/company-threat-analyzer
```

## Variables de Entorno

| Variable | Requerida | Por defecto | Descripción |
|----------|-----------|-------------|-------------|
| `OPENCLAW_AI_MODEL` | No | `microsoft/codebert-base` | Identificador de modelo (ruta local o ID de HuggingFace) |
| `THREAT_SCAN_CONFIDENCE` | No | `0.7` | Umbral mínimo de confianza (0.0-1.0) |
| `OPENCLAW_AI_API_KEY` | Condicional | - | Requerida para API de modelo IA remoto (ej. OpenAI, Anthropic, endpoint personalizado) |
| `OPENCLAW_AI_API_ENDPOINT` | Condicional | - | Endpoint API personalizado si no se usa HuggingFace por defecto |
| `THREAT_SCAN_MAX_TOKENS` | No | `4096` | Tokens máximos para entrada del modelo IA |
| `THREAT_SCAN_BATCH_SIZE` | No | `16` | Tamaño de lote para inferencia del modelo |

**Ejemplo de archivo .env:**
```bash
OPENCLAW_AI_MODEL="./models/custom-analyzer-v2.1"
THREAT_SCAN_CONFIDENCE=0.8
OPENCLAW_AI_API_KEY="hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
THREAT_SCAN_MAX_TOKENS=2048
```

## Dependencias y Requisitos

**Requisitos del Sistema:**
- Python 3.9+ con pip
- Docker (para entornos de escaneo containerizados)
- Git (para creación de PR y gestión de backups)
- 8GB RAM mínimo, 16GB recomendado para inferencia IA
- 10GB espacio en disco para modelos y datasets

**Paquetes Python (instalados automáticamente):**
```
transformers>=4.30.0
torch>=2.0.0
sentencepiece
accelerate
bandit>=1.7.5
semgrep>=1.50.0
trivy>=0.45.0
grype>=0.75.0
jq (CLI tool)
sarif-tools (CLI tool)
```

**Dependencias Opcionales:**
- `radon` - para análisis de complejidad de código
- `safety` - Base de datos de vulnerabilidades Python
- `npm-audit` o `yarn-audit` - Escáneres de vulnerabilidades JavaScript
- `checkov` - escáner adicional de infraestructura como código
- `gitleaks` - detección de secrets

**Configuración Única:**
```bash
# Instalar dependencias del sistema
sudo apt-get update && sudo apt-get install -y jq docker.io git

# Instalar dependencias de habilidad OpenClaw (manejado automáticamente por la habilidad)
openclaw skill ai-threat-analyzer install-deps

# Descargar modelo IA (si no se usa API remota)
openclaw skill ai-threat-analyzer download-model microsoft/codebert-base
```

## Solución de Problemas

### "CUDA out of memory" durante escaneo
**Síntomas:** Proceso terminado con error CUDA durante análisis IA
**Solución:**
```bash
# Reducir tamaño de lote
export THREAT_SCAN_BATCH_SIZE=4
# Usar CPU en lugar de GPU
export CUDA_VISIBLE_DEVICES=""
# O añadir flag: --device=cpu
```

### Error "Model not found"
**Síntomas:** `OSError: Model name '...' was not found`
**Solución:**
```bash
# Asegurar que el modelo existe localmente o es ID correcto de HuggingFace
huggingface-cli login  # Si se accede a modelo privado
openclaw skill ai-threat-analyzer download-model <id-de-modelo-correcto>
# Para modelo local: --model=./ruta/relativa/al/modelo
```

### Inundación de falsos positivos en codebase
**Síntomas:** Cientos de advertencias de baja confianza ahogando la señal
**Solución:**
```bash
# Aumentar umbral de confianza
export THREAT_SCAN_CONFIDENCE=0.85
# Añadir exclusiones específicas
openclaw skill ai-threat-analyzer scan-code ./src --exclude '**/tests/**' --exclude '**/migrations/**'
# Construir lista de supresión desde falsos positivos y reentrenar
openclaw skill ai-threat-analyzer train-model ./false-positives.jsonl --base-model=./models/current --epochs=1
```

### Docker no ejecutándose (para entornos de escaneo aislados)
**Síntomas:** `docker: command not found` o `Cannot connect to the Docker daemon`
**Solución:**
```bash
# Iniciar servicio Docker
sudo systemctl start docker
sudo systemctl enable docker
# Añadir usuario al grupo docker (luego re-login)
sudo usermod -aG docker $USER
```

### Escaneo de dependencias sin CVEs detectados
**Síntomas:** No se encuentran vulnerabilidades, pero `npm audit` muestra problemas conocidos
**Solución:**
```bash
# Asegurar que la base de datos de vulnerabilidades esté actualizada
trivy image --update
grype db update
# Re-escanear con profundidad mayor
openclaw skill ai-threat-analyzer scan-deps ./package.json --depth 10
```

### Fallo en creación de PR (GitHub)
**Síntomas:** `gh: command not found` o errores de autenticación
**Solución:**
```bash
# Instalar GitHub CLI
sudo apt-get install gh
gh auth login  # Seguir flujo OAuth
# Asegurar que el repositorio tiene permisos para crear PR
gh repo view
# Usar SSH en lugar de HTTPS si es necesario
git remote set-url origin git@github.com:org/repo.git
```

### Escaneos lentos en codebases grandes
**Síntomas:** Escaneos tomando >1 hora para proyectos de tamaño moderado
**Solución:**
```bash
# Ejecutar escaneos en paralelo con make o GNU parallel
find . -name "*.py" -type f | parallel "openclaw skill ai-threat-analyzer explain-finding {}" &
wait
# Cachear modelo entre ejecuciones (automático en primera carga)
# Usar --exclude para omitir código de vendor/terceros
openclaw skill ai-threat-analyzer scan-code . --exclude '**/node_modules/**' --exclude '**/.venv/**'
```

### "API rate limit exceeded" (IA remota)
**Síntomas:** HTTP 429 desde `api.openai.com` o similar
**Solución:**
```bash
# Cambiar a modelo local para escaneos bulk
export OPENCLAW_AI_MODEL="./models/local-model"
# O solicitar aumento de cuota en tu proveedor IA
# Implementar retroceso exponencial:
export THREAT_SCAN_RETRIES=3
export THREAT_SCAN_RETRY_DELAY=5
```
```