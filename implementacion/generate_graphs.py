#!/usr/bin/env python3
"""
Generate performance graphs for GFRX+COFB thesis
Author: Fernando Ramirez Arredondo
Date: 2025-11-18
"""

import matplotlib.pyplot as plt
import matplotlib
import numpy as np

# Use non-interactive backend
matplotlib.use('Agg')

# Set professional style
plt.style.use('seaborn-v0_8-darkgrid')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['legend.fontsize'] = 10

# Performance data from COMPARACION_RESULTADOS.md
message_sizes = [16, 64, 256, 1024, 4096, 16384]  # bytes

# Throughput data (Mbps)
throughput_gfrx = [289.11, 616.90, 889.27, 871.33, 552.84, 220.91]
throughput_ascon = [191.01, 394.10, 532.51, 594.57, 611.32, 600.81]
throughput_aes_gcm = [112.16, 506.48, 1864.40, 7116.39, 23811.68, 54902.33]

# Latency data (microseconds)
latency_gfrx = [0.443, 0.830, 2.303, 9.402, 59.272, 593.337]
latency_ascon = [0.670, 1.299, 3.846, 13.778, 53.602, 218.159]
latency_aes_gcm = [1.141, 1.011, 1.098, 1.151, 1.376, 2.387]


def generate_throughput_graph():
    """Generate throughput vs message size comparison graph"""
    fig, ax = plt.subplots()

    # Plot lines
    ax.plot(message_sizes, throughput_gfrx, 'o-', linewidth=2, markersize=8,
            label='GFRX+COFB', color='#2E86AB')
    ax.plot(message_sizes, throughput_ascon, 's-', linewidth=2, markersize=8,
            label='ASCON-128', color='#A23B72')
    ax.plot(message_sizes, throughput_aes_gcm, '^-', linewidth=2, markersize=8,
            label='AES-128-GCM', color='#F18F01')

    # Labels and title
    ax.set_xlabel('Tamaño de Mensaje (bytes)', fontweight='bold')
    ax.set_ylabel('Throughput (Mbps)', fontweight='bold')
    ax.set_title('Comparación de Throughput: GFRX+COFB vs ASCON vs AES-GCM',
                 fontweight='bold', pad=20)

    # Log scale for x-axis (message sizes vary widely)
    ax.set_xscale('log')
    ax.set_yscale('log')

    # Grid
    ax.grid(True, alpha=0.3, linestyle='--')

    # Legend
    ax.legend(loc='best', framealpha=0.9)

    # Annotations for key points
    # GFRX+COFB wins at 16 bytes
    ax.annotate('GFRX+COFB\nmejor (289 Mbps)',
                xy=(16, 289.11), xytext=(20, 400),
                arrowprops=dict(arrowstyle='->', color='#2E86AB', lw=1.5),
                fontsize=9, ha='left', color='#2E86AB', fontweight='bold')

    # AES-GCM dominates at 16KB
    ax.annotate('AES-GCM\ndomina (55 Gbps)',
                xy=(16384, 54902.33), xytext=(10000, 30000),
                arrowprops=dict(arrowstyle='->', color='#F18F01', lw=1.5),
                fontsize=9, ha='center', color='#F18F01', fontweight='bold')

    plt.tight_layout()
    plt.savefig('throughput_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Generated: throughput_comparison.png")
    plt.close()


def generate_latency_graph():
    """Generate latency comparison bar chart"""
    fig, ax = plt.subplots()

    # Select specific message sizes for clarity (not all)
    selected_sizes = [16, 64, 256, 1024]
    selected_indices = [0, 1, 2, 3]

    x = np.arange(len(selected_sizes))
    width = 0.25

    # Create bars
    bars1 = ax.bar(x - width, [latency_gfrx[i] for i in selected_indices],
                   width, label='GFRX+COFB', color='#2E86AB', alpha=0.8)
    bars2 = ax.bar(x, [latency_ascon[i] for i in selected_indices],
                   width, label='ASCON-128', color='#A23B72', alpha=0.8)
    bars3 = ax.bar(x + width, [latency_aes_gcm[i] for i in selected_indices],
                   width, label='AES-128-GCM', color='#F18F01', alpha=0.8)

    # Labels
    ax.set_xlabel('Tamaño de Mensaje (bytes)', fontweight='bold')
    ax.set_ylabel('Latencia (microsegundos)', fontweight='bold')
    ax.set_title('Comparación de Latencia para Mensajes Pequeños (IoT)',
                 fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(selected_sizes)

    # Grid
    ax.grid(True, alpha=0.3, linestyle='--', axis='y')

    # Legend
    ax.legend(loc='upper left', framealpha=0.9)

    # Add value labels on bars
    def autolabel(bars):
        for bar in bars:
            height = bar.get_height()
            ax.annotate(f'{height:.2f}',
                       xy=(bar.get_x() + bar.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=8)

    autolabel(bars1)
    autolabel(bars2)
    autolabel(bars3)

    plt.tight_layout()
    plt.savefig('latency_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Generated: latency_comparison.png")
    plt.close()


def generate_efficiency_graph():
    """Generate efficiency metrics (Mbps per byte of state)"""
    fig, ax = plt.subplots()

    # State sizes (bits -> bytes)
    state_gfrx = 320 / 8  # 40 bytes
    state_ascon = 320 / 8  # 40 bytes
    state_aes_gcm = 384 / 8  # 48 bytes

    # Calculate efficiency for 256-byte messages (typical IoT)
    idx_256 = 2  # index for 256 bytes
    efficiency_gfrx = throughput_gfrx[idx_256] / state_gfrx
    efficiency_ascon = throughput_ascon[idx_256] / state_ascon
    efficiency_aes_gcm = throughput_aes_gcm[idx_256] / state_aes_gcm

    schemes = ['GFRX+COFB', 'ASCON-128', 'AES-128-GCM']
    efficiency = [efficiency_gfrx, efficiency_ascon, efficiency_aes_gcm]
    colors = ['#2E86AB', '#A23B72', '#F18F01']

    bars = ax.bar(schemes, efficiency, color=colors, alpha=0.8, edgecolor='black', linewidth=1.5)

    # Labels
    ax.set_ylabel('Eficiencia (Mbps / byte de estado)', fontweight='bold')
    ax.set_title('Eficiencia de Estado (256 bytes - caso IoT típico)',
                 fontweight='bold', pad=20)

    # Grid
    ax.grid(True, alpha=0.3, linestyle='--', axis='y')

    # Add value labels on bars
    for bar, val in zip(bars, efficiency):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{val:.1f}',
                ha='center', va='bottom', fontweight='bold', fontsize=11)

    # Add state size annotations
    state_sizes = [state_gfrx, state_ascon, state_aes_gcm]
    for i, (bar, state) in enumerate(zip(bars, state_sizes)):
        ax.text(bar.get_x() + bar.get_width()/2., 5,
                f'Estado: {int(state*8)} bits',
                ha='center', va='bottom', fontsize=9, style='italic')

    plt.tight_layout()
    plt.savefig('efficiency_comparison.png', dpi=300, bbox_inches='tight')
    print("✓ Generated: efficiency_comparison.png")
    plt.close()


def generate_small_message_focus():
    """Generate graph focusing on small messages (IoT sweet spot)"""
    fig, ax = plt.subplots()

    # Focus on 16-256 bytes (typical IoT)
    small_sizes = message_sizes[:3]
    small_gfrx = throughput_gfrx[:3]
    small_ascon = throughput_ascon[:3]
    small_aes_gcm = throughput_aes_gcm[:3]

    x = np.arange(len(small_sizes))
    width = 0.25

    bars1 = ax.bar(x - width, small_gfrx, width, label='GFRX+COFB',
                   color='#2E86AB', alpha=0.8, edgecolor='black')
    bars2 = ax.bar(x, small_ascon, width, label='ASCON-128',
                   color='#A23B72', alpha=0.8, edgecolor='black')
    bars3 = ax.bar(x + width, small_aes_gcm, width, label='AES-128-GCM',
                   color='#F18F01', alpha=0.8, edgecolor='black')

    ax.set_xlabel('Tamaño de Mensaje (bytes)', fontweight='bold')
    ax.set_ylabel('Throughput (Mbps)', fontweight='bold')
    ax.set_title('Rendimiento en Mensajes Pequeños (Escenario IoT)',
                 fontweight='bold', pad=20)
    ax.set_xticks(x)
    ax.set_xticklabels(small_sizes)

    ax.grid(True, alpha=0.3, linestyle='--', axis='y')
    ax.legend(loc='upper left', framealpha=0.9)

    # Add advantage annotations
    ax.text(0, small_gfrx[0] + 30, '1.5x más\nrápido', ha='center',
            fontsize=9, color='#2E86AB', fontweight='bold')

    plt.tight_layout()
    plt.savefig('small_message_performance.png', dpi=300, bbox_inches='tight')
    print("✓ Generated: small_message_performance.png")
    plt.close()


def generate_summary_table_image():
    """Generate a summary table as an image"""
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.axis('tight')
    ax.axis('off')

    # Data for table
    table_data = [
        ['Esquema', 'Estado\n(bits)', '16 bytes\n(Mbps)', '64 bytes\n(Mbps)',
         '256 bytes\n(Mbps)', '1 KB\n(Mbps)', 'Mejor para'],
        ['GFRX+COFB', '320', '289', '617', '889', '871',
         'IoT, mensajes\npequeños'],
        ['ASCON-128', '320', '191', '394', '533', '595',
         'Balance\ngeneral'],
        ['AES-128-GCM', '384', '112', '506', '1,864', '7,116',
         'Mensajes\ngrandes']
    ]

    # Each row has 7 columns
    num_cols = 7
    colors = [['#E8E8E8']*num_cols,  # Header
              ['#D6EAF8']*num_cols,  # GFRX (light blue)
              ['#F5CED4']*num_cols,  # ASCON (light purple)
              ['#FCE8D1']*num_cols]  # AES-GCM (light orange)

    table = ax.table(cellText=table_data, cellLoc='center', loc='center',
                     cellColours=colors, bbox=[0, 0, 1, 1])

    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2.5)

    # Bold header
    for i in range(num_cols):
        table[(0, i)].set_text_props(weight='bold', fontsize=11)

    plt.title('Resumen de Rendimiento: GFRX+COFB vs ASCON vs AES-GCM',
              fontweight='bold', fontsize=14, pad=20)

    plt.savefig('performance_summary_table.png', dpi=300, bbox_inches='tight')
    print("✓ Generated: performance_summary_table.png")
    plt.close()


def main():
    """Generate all graphs"""
    print("\n" + "="*60)
    print("Generating Performance Graphs for GFRX+COFB Thesis")
    print("="*60 + "\n")

    try:
        generate_throughput_graph()
        generate_latency_graph()
        generate_efficiency_graph()
        generate_small_message_focus()
        generate_summary_table_image()

        print("\n" + "="*60)
        print("✓ All graphs generated successfully!")
        print("="*60)
        print("\nGenerated files:")
        print("  1. throughput_comparison.png")
        print("  2. latency_comparison.png")
        print("  3. efficiency_comparison.png")
        print("  4. small_message_performance.png")
        print("  5. performance_summary_table.png")
        print("\nThese can be included in the thesis chapters.")

    except Exception as e:
        print(f"\n✗ Error generating graphs: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
